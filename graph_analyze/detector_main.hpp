#pragma once

#include "../packet_parse/pcap_parser.hpp"
#include "../flow_construct/explicit_constructor.hpp"
#include "edge_constructor.hpp"
#include "graph_define.hpp"
#include <pcapplusplus/PcapLiveDeviceList.h>
#include <pcapplusplus/SystemUtils.h>
#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/UdpLayer.h>
#include <pcapplusplus/IpLayer.h>


namespace Hypervision
{

    void coutIP(int ip) {
        std::cout << (ip & 255) << '.'
                  << (ip >> 8 & 255) << '.'
                  << (ip >> 16 & 255) << '.'
                  << (ip >> 24 & 255);
    }

    shared_ptr<basic_packet4> parsePacket(pcpp::RawPacket* packet) {
        pcpp::Packet parsedPacket(packet, false, pcpp::IP, pcpp::OsiModelNetworkLayer);
        pkt_addr4_t s4, d4;
        pkt_code_t packet_code = 0;
        pkt_ts_t packet_time = packet->getPacketTimeStamp();
        pkt_port_t s_port = 0, d_port = 0;
        pkt_len_t packet_length = 0;

        auto _f_parse_udp = [&parsedPacket, &s_port, &d_port, &packet_code] () -> void {
            pcpp::UdpLayer * p_udp_layer = parsedPacket.getLayerOfType<pcpp::UdpLayer>();
            s_port = htons(p_udp_layer->getUdpHeader()->portSrc);
            d_port = htons(p_udp_layer->getUdpHeader()->portDst);
            set_pkt_type_code(packet_code, pkt_type_t::UDP);
        };

        auto _f_parse_tcp = [&parsedPacket, &s_port, &d_port, &packet_code] () -> void {
            pcpp::TcpLayer * p_tcp_layer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();
            s_port = htons(p_tcp_layer->getTcpHeader()->portSrc);
            d_port = htons(p_tcp_layer->getTcpHeader()->portDst);
            if (p_tcp_layer->getTcpHeader()->synFlag) {
                set_pkt_type_code(packet_code, pkt_type_t::TCP_SYN);
            }
            if (p_tcp_layer->getTcpHeader()->finFlag) {
                set_pkt_type_code(packet_code, pkt_type_t::TCP_FIN);
            }
            if (p_tcp_layer->getTcpHeader()->rstFlag) {
                set_pkt_type_code(packet_code, pkt_type_t::TCP_RST);
            }
            if (p_tcp_layer->getTcpHeader()->ackFlag) {
                set_pkt_type_code(packet_code, pkt_type_t::TCP_ACK);
            }
        };
        pcpp::IPv4Layer * p_IPv4_layer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
        set_pkt_type_code(packet_code, pkt_type_t::IPv4);

        if (p_IPv4_layer == nullptr) {
            return nullptr;
        }
        s4 = p_IPv4_layer->getSrcIPv4Address().toInt();
        d4 = p_IPv4_layer->getDstIPv4Address().toInt();
        packet_length = htons(p_IPv4_layer->getIPv4Header()->totalLength);
        p_IPv4_layer->parseNextLayer();

        pcpp::ProtocolType type_next;
        if (p_IPv4_layer->getNextLayer() == nullptr) {
            type_next = pcpp::UnknownProtocol;
        } else {
            type_next = p_IPv4_layer->getNextLayer()->getProtocol();
        }
        switch (type_next) {
        case pcpp::TCP:
            _f_parse_tcp();
            break;
        case pcpp::UDP:
            _f_parse_udp();
            break;
        case pcpp::ICMP:
            set_pkt_type_code(packet_code, pkt_type_t::ICMP);
            break;
        case pcpp::IGMP:
            set_pkt_type_code(packet_code, pkt_type_t::IGMP);
            break;
        default:
            set_pkt_type_code(packet_code, pkt_type_t::UNKNOWN);
            break;
        }
        return make_shared<basic_packet4>(s4, d4, s_port, d_port, packet_time, packet_code, packet_length);
    }

    bool onPacketArrives(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* cookie) {
        auto p_parse_result = *static_cast<shared_ptr<vector<shared_ptr<basic_packet> > >*>(cookie);
        auto p = parsePacket(packet);
        if (p == nullptr) {
            return false;
        }
        p_parse_result->push_back(parsePacket(packet));
        if (p_parse_result->size() >= 20000000) {
            p_parse_result->erase(p_parse_result->begin(), p_parse_result->begin() + 10000000);
        }
        return false;
    }


class hypervision_detector {
private:

    json jin_main;
    string file_path = "";
    
    shared_ptr<vector<shared_ptr<basic_packet> > > p_parse_result;
    
    shared_ptr<binary_label_t> p_label;
    shared_ptr<vector<double_t> > p_loss;
    
    shared_ptr<vector<shared_ptr<basic_flow> > > p_flow;

    shared_ptr<vector<shared_ptr<short_edge> > > p_short_edges;
    shared_ptr<vector<shared_ptr<long_edge> > > p_long_edges;


    bool save_result_enable = false;
    string save_result_path = "../temp/default.json";

public:
    void useBenignBackground(void) {
        p_parse_result = make_shared<decltype(p_parse_result)::element_type>();
        p_label = make_shared<decltype(p_label)::element_type>();

        const auto p_dataset_constructor = make_shared<basic_dataset>(p_parse_result);
        p_dataset_constructor->configure_via_json(jin_main["dataset_construct"]);
        p_dataset_constructor->import_dataset();
        auto label = p_dataset_constructor->get_label();
        auto result = p_dataset_constructor->get_raw_pkt();
        for (int i = 0; i < result->size(); i++) {
            if (!label->at(i)) {
                p_parse_result->push_back(result->at(i));
                p_label->push_back(label->at(i));
            }
        }
        std::cout << "Using " << p_parse_result->size() << " benign background" << std::endl;
    }

    void analyze(void) {
        LOGF("Construct flow.");
        const auto p_flow_constructor = make_shared<explicit_flow_constructor>(p_parse_result);
        p_flow_constructor->config_via_json(jin_main["flow_construct"]);
        p_flow_constructor->construct_flow();
        p_flow = p_flow_constructor->get_constructed_raw_flow();

        LOGF("Construct edge.");
        const auto p_edge_constructor = make_shared<edge_constructor>(p_flow);
        p_edge_constructor->config_via_json(jin_main["edge_construct"]);
        p_edge_constructor->do_construct();
        tie(p_short_edges, p_long_edges) = p_edge_constructor->get_edge();

        LOGF("Construct Graph.");
        const auto p_graph = make_shared<traffic_graph>(p_short_edges, p_long_edges);
        p_graph->config_via_json(jin_main["graph_analyze"]);
        p_graph->parse_edge();
        p_graph->graph_detect();
        p_loss = p_graph->get_final_pkt_score(p_label);

        std::map<tuple2_conn4, pair<int,double> > m;
        for (size_t i = 0; i < p_loss->size(); ++ i) {
            if (p_loss->at(i) > 11) {
                auto flow_id = dynamic_pointer_cast<basic_packet4>(p_parse_result->at(i))->flow_id;
                auto id = tuple2_conn4(tuple_get_src_addr(flow_id), tuple_get_dst_addr(flow_id));
                m[id] = make_pair(m[id].first + 1, max(m[id].second, p_loss->at(i)));
            }
        }
        for (auto x : m) {
            auto flow_id = x.first;
            std::cout << "malicious: [" << x.second.first << ":" << x.second.second << "]" << ' ';
            coutIP(tuple_get_src_addr(flow_id));
            std::cout << " -> ";
            coutIP(tuple_get_dst_addr(flow_id));
            std::cout << std::endl;
        }
    }

    void start(void) {
        __START_FTIMMER__

        if (jin_main.count("use_pcap")) {
            useBenignBackground();
            const auto p_packet_parser = make_shared<pcap_parser>(jin_main["use_pcap"]);
            p_packet_parser->parse_raw_packet();
            p_packet_parser->parse_basic_packet_fast();
            auto result = p_packet_parser->get_basic_packet_rep();
            for (int i = 0; i < result->size(); i++) {
                p_parse_result->push_back(result->at(i));
            }
            fill_n(back_inserter(*p_label), p_parse_result->size(), true);
        } else if (jin_main.count("live_capture_device_by_ip")) {
            useBenignBackground();
            std::string interfaceIPAddr = jin_main["live_capture_device_by_ip"];
            auto* dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(interfaceIPAddr);
            if (dev == nullptr) {
                std::cerr << "dev == nullptr" << std::endl;
                return;
            }
            std::cout << "Interface info:" << std::endl;
            std::cout << "  Interface name:        " << dev->getName() << std::endl;
            std::cout << "  Interface description: " << dev->getDesc() << std::endl;
            std::cout << "  MAC address:           " << dev->getMacAddress() << std::endl;
            std::cout << "  Default gateway:       " << dev->getDefaultGateway() << std::endl;
            std::cout << "  Interface MTU:         " << dev->getMtu() << std::endl;
            if (!dev->open()) {
                std::cerr << "!dev->open()" << std::endl;
                return;
            }
            std::cout << "Start capturing..." << std::endl;
            while (true) {
                int x = dev->startCaptureBlockingMode(onPacketArrives, &p_parse_result, 10);
                if (x < 0) {
                    // std::cout << "timeout at " << p_parse_result->size() << " packets" << std::endl;
                } else if (x > 0) {
                    // std::cout << "limit reached at " << p_parse_result->size() << " packets" << std::endl;
                } else {
                    std::cout << "error at " << p_parse_result->size() << " packets" << std::endl;
                    break;
                }
                std::cout << "Captured " << p_parse_result->size() << " packets" << std::endl;
                while (p_label->size() > p_parse_result->size()) {
                    p_label->pop_back();
                }
                while (p_label->size() < p_parse_result->size()) {
                    p_label->push_back(false);
                }
                analyze();
            }
        } else if (jin_main.count("packet_parse") &&
            jin_main["packet_parse"].count("target_file_path")) {
            
            LOGF("Parse packet from file.");
            file_path = jin_main["packet_parse"]["target_file_path"];
            const auto p_packet_parser = make_shared<pcap_parser>(file_path);
            p_packet_parser->parse_raw_packet();
            p_packet_parser->parse_basic_packet_fast();
            p_parse_result = p_packet_parser->get_basic_packet_rep();

            LOGF("Split datasets.");
            const auto p_dataset_constructor = make_shared<basic_dataset>(p_parse_result);
            p_dataset_constructor->configure_via_json(jin_main["dataset_construct"]);
            p_dataset_constructor->do_dataset_construct();
            p_label = p_dataset_constructor->get_label();

        } else if (jin_main["dataset_construct"].count("data_path") && 
                    jin_main["dataset_construct"].count("label_path")){
            LOGF("Load & split datasets.");
            const auto p_dataset_constructor = make_shared<basic_dataset>(p_parse_result);
            p_dataset_constructor->configure_via_json(jin_main["dataset_construct"]);
            p_dataset_constructor->import_dataset();
            p_label = p_dataset_constructor->get_label();
            p_parse_result = p_dataset_constructor->get_raw_pkt();
            std::cout << "Analyzing " << p_parse_result->size() << " packets" << std::endl;
            int malicious = 0;
            int benign = 0;
            for (int i = 0; i < p_label->size(); i++) {
                if (p_label->at(i)) {
                    malicious++;
                } else {
                    benign++;
                }
            }
            std::cout << benign << " benign" << std::endl;
            std::cout << malicious << " malicious" << std::endl;
        } else {
            LOGF("Dataset not found.");
        }
        analyze();

        if (save_result_enable) {
            do_save(save_result_path);
        }

        __STOP_FTIMER__
        __PRINTF_EXE_TIME__

    }

    void config_via_json(const json & jin) {
        try {
            if (
                jin.count("dataset_construct") &&
                jin.count("flow_construct") &&
                jin.count("edge_construct") &&
                jin.count("graph_analyze") &&
                jin.count("result_save")) {
                    jin_main = jin;
                } else {
                    throw logic_error("Incomplete json configuration.");
                }
                const auto j_save = jin["result_save"];
                if (j_save.count("save_result_enable")) {
                    save_result_enable = static_cast<decltype(save_result_enable)>(j_save["save_result_enable"]);
                }
                if (j_save.count("save_result_path")) {
                    save_result_path = static_cast<decltype(save_result_path)>(j_save["save_result_path"]);
                }
        } catch (const exception & e) {
            FATAL_ERROR(e.what());
        }
    }

    void do_save(const string & save_path) {
        __START_FTIMMER__

        ofstream _f(save_path);
        if (_f.is_open()) {
            try {
                _f << setprecision(4);
                for (size_t i = 0; i < p_label->size(); ++i) {
                    _f << p_label->at(i) << ' '<< p_loss->at(i) << '\n';
                    if (i % 1000 == 0) {
                        _f << flush;
                    }
                }
            } catch(const exception & e) {
                FATAL_ERROR(e.what());
            }
            _f.close();
        } else {
            FATAL_ERROR("File Error.");
        }
        
        __STOP_FTIMER__
        __PRINTF_EXE_TIME__
    }

};

}
