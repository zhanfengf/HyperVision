#include "graph_define.hpp"


using namespace Hypervision;


void traffic_graph::hkuspace_assert_components(const shared_ptr<component> components) {
    // Double check if components contains all addresses
    std::unordered_set<addr_t> assert_pigeon;
    for (size_t i = 0; i < components->size(); ++i) {
        const auto& comp = (*components)[i];
        for (const auto& addr : comp) {
            if (assert_pigeon.count(addr)) {
                // std::cout << "Assert pigeon component duplicated " << addr << std::endl;
            }
            assert_pigeon.insert(addr);
        }
    }
    for (const auto& pair : long_edge_out) {
        if (!assert_pigeon.count(pair.first)) {
            std::cout << "Assert pigeon component missing " << pair.first << std::endl;
        }
    }
    for (const auto& pair : long_edge_in) {
        if (!assert_pigeon.count(pair.first)) {
            std::cout << "Assert pigeon component missing " << pair.first << std::endl;
        }
    }
    for (const auto& pair : short_edge_out) {
        if (!assert_pigeon.count(pair.first)) {
            std::cout << "Assert pigeon component missing " << pair.first << std::endl;
        }
    }
    for (const auto& pair : short_edge_in) {
        if (!assert_pigeon.count(pair.first)) {
            std::cout << "Assert pigeon component missing " << pair.first << std::endl;
        }
    }
    for (const auto& pair : short_edge_out_agg) {
        if (!assert_pigeon.count(pair.first)) {
            std::cout << "Assert pigeon component missing " << pair.first << std::endl;
        }
    }
    for (const auto& pair : short_edge_in_agg) {
        if (!assert_pigeon.count(pair.first)) {
            std::cout << "Assert pigeon component missing " << pair.first << std::endl;
        }
    }
}


void traffic_graph::hkuspace_export_components(const shared_ptr<binary_label_t> p_label,
                                               const std::string & filename) {
    __START_FTIMMER__
    const auto _f_extract_feature_component = [&] (const component::value_type & cp) -> feature_t {
        unordered_set<size_t> _long_index, _short_index, _short_agg_index;
        _acquire_edge_index(cp, _long_index, _short_index);
        size_t byte_ctr_long = 0, byte_ctr_short = 0;
        for (const size_t idx: _long_index) {
            const auto db_ref = p_long_edge->at(idx)->get_length_distribution();
            for (const auto & ref: *db_ref) {
                byte_ctr_long += ref.second;
            }
        }
        for (const size_t idx: _short_index) {
            const auto pk_ref = p_short_edge->at(idx)->get_flow_index(0);
            const auto edge_size = p_short_edge->at(idx)->get_agg_size();
            size_t acc = 0;
            for (const auto p_p: *pk_ref->get_p_packet_p_seq()) {
                acc += p_p->len;
            }
            byte_ctr_short += acc * edge_size;
        }
        return {
            (double) cp.size(),
            (double) _long_index.size(),
            (double) _short_index.size(),
            (double) _short_agg_index.size(),
            (double) byte_ctr_long,
            (double) byte_ctr_short
        };
    };
    shared_ptr<component> components = hkuspace_components;
    hkuspace_assert_components(components);
    const auto p_select = hkuspace_selected_components;
    std::ofstream file(filename, std::ios::out);
    if (!file.is_open()) {
        std::cerr << "Error opening file for writing!" << std::endl;
        return;
    }

    // Write CSV header
    file << "ComponentID,Selected,NumVertices,LivePacketsCount,MaliciousCount,LongEdges,ShortEdges,ShortAggEdges,BytesLong,BytesShort\n";

    // Iterate over components
    int missed_malicious_packets = 0;
    for (size_t i = 0; i < components->size(); ++i) {
        const auto& comp = (*components)[i];
        size_t malicious_packets = 0, total_packets = 0, live_packets = 0;

        // Track flows associated with component addresses
        std::unordered_set<shared_ptr<basic_flow>> relevant_flows;

        for (const auto& addr : comp) {
            // Check long edges for flows linked to component addresses
            if (long_edge_out.count(addr)) {
                for (const auto& edge_idx : long_edge_out.at(addr)) {
                    relevant_flows.insert(p_long_edge->at(edge_idx)->get_raw_flow());
                }
            }
            if (long_edge_in.count(addr)) {
                for (const auto& edge_idx : long_edge_in.at(addr)) {
                    relevant_flows.insert(p_long_edge->at(edge_idx)->get_raw_flow());
                }
            }
            // Check short edges for flows linked to component addresses
            if (short_edge_out.count(addr)) {
                for (const auto& edge_idx : short_edge_out.at(addr)) {
                    for (size_t j = 0; j < p_short_edge->at(edge_idx)->get_agg_size(); ++ j) {
                        relevant_flows.insert(p_short_edge->at(edge_idx)->get_flow_index(j));
                    }
                }
            }
            if (short_edge_in.count(addr)) {
                for (const auto& edge_idx : short_edge_in.at(addr)) {
                    for (size_t j = 0; j < p_short_edge->at(edge_idx)->get_agg_size(); ++ j) {
                        relevant_flows.insert(p_short_edge->at(edge_idx)->get_flow_index(j));
                    }
                }
            }
            if (short_edge_out_agg.count(addr)) {
                for (const auto& edge_idx : short_edge_out_agg.at(addr)) {
                    for (size_t j = 0; j < p_short_edge->at(edge_idx)->get_agg_size(); ++ j) {
                        relevant_flows.insert(p_short_edge->at(edge_idx)->get_flow_index(j));
                    }
                }
            }
            if (short_edge_in_agg.count(addr)) {
                for (const auto& edge_idx : short_edge_in_agg.at(addr)) {
                    for (size_t j = 0; j < p_short_edge->at(edge_idx)->get_agg_size(); ++ j) {
                        relevant_flows.insert(p_short_edge->at(edge_idx)->get_flow_index(j));
                    }
                }
            }
        }

        // Scan packets in relevant flows to determine malicious ratio
        for (const auto& flow : relevant_flows) {
            for (const auto& packet_idx : *flow->get_p_reverse_id()) {
                if (packet_idx < p_label->size()) {
                    total_packets++;
                    if (p_label->at(packet_idx)) {
                        malicious_packets++;
                    }
                } else {
                    live_packets++;
                }
            }
        }

        // Compute malicious ratio
        double malicious_ratio = (total_packets > 0) ? ((double)malicious_packets / total_packets) : 0.0;

        int selected = 0;
        for (const auto index: *p_select) {
            if (index == i) {
                selected = 1;
                break;
            }
        }
        if (selected) {
            std::cout << "Component " << i << " has " << malicious_packets << " malicious packets" << std::endl;
        } else {
            missed_malicious_packets += malicious_packets;
        }
        // Write component data to CSV
        file << i << "," << selected << "," << comp.size() << "," << live_packets << "," << malicious_packets << ",";
        feature_t features = _f_extract_feature_component(comp);

        // Write component data to CSV
        file << features[1] << "," << features[2] << "," << features[3] << ","
             << features[4] << "," << features[5];
        // List addresses within the component
        // for (size_t j = 0; j < comp.size(); ++j) {
            // file << comp[j];
            // if (j < comp.size() - 1) file << ";";
        // }

        file << "\n";
    }
    std::cout << "Missed " << missed_malicious_packets << " malicious packets" << std::endl;
    file.close();
    std::cout << "Components successfully exported to: " << filename << std::endl;
    __STOP_FTIMER__
    __PRINTF_EXE_TIME__
}

auto traffic_graph::connected_component() const -> shared_ptr<component> {
    __START_FTIMMER__
    LOGF("Detect strong connected conponents.");

    vector<addr_t> _vertex_reverse;
    set_union(vertex_set_long.cbegin(), vertex_set_long.cend(), vertex_set_short_reduce.cbegin(), 
                vertex_set_short_reduce.cend(), back_inserter(_vertex_reverse));
    set<addr_t> _ss(_vertex_reverse.cbegin(), _vertex_reverse.cend());
    _vertex_reverse.clear();
    _vertex_reverse.assign(_ss.cbegin(), _ss.cend());

    map<addr_t, size_t> _vertex;
    vector<vector<size_t> > _graph(_vertex_reverse.size());
    for (size_t i = 0; i < _vertex_reverse.size(); ++i) {
        if (_vertex.count(_vertex_reverse[i])) {
            WARNF("Warning: Symbol - %s.", _vertex_reverse[i].c_str());
        } else {
            _vertex.insert({_vertex_reverse[i], i});
        }
    }

    for (const auto & ref: _vertex) {
        assert(ref.first == _vertex_reverse.at(ref.second));
    }

    vector<pair<size_t, size_t> > _edge_raw;
    for (const auto & ref: long_edge_out) {
        for (const auto idx: ref.second) {
            _edge_raw.push_back({
                _vertex[ref.first], _vertex[p_long_edge->at(idx)->get_dst_str()]
            });
        }
    }
    for (const auto & ref: short_edge_out) {
        for (const auto idx: ref.second) {
            _edge_raw.push_back({
                _vertex[ref.first], _vertex[p_short_edge->at(idx)->get_dst_str()]
            });
        }
    }

    for (const auto & ref: _edge_raw) {
        assert(ref.first != ref.second);
        assert(ref.first < _vertex.size());
        assert(ref.second < _vertex.size());
        _graph[ref.first].push_back(ref.second);
        _graph[ref.second].push_back(ref.first);
    }

    vector<bool> _mk(_vertex.size(), false);

    vector<vector<size_t> > parts;
    for (const auto & ref : _vertex) {
        
        if (!_mk[ref.second]) {
            decltype(parts)::value_type _part;

            const function<void(const size_t, decltype(_part) &)> _f_dfs = 
            [&] (const size_t _idx, decltype(_part) & _ptr) -> void {
                _mk[_idx] = true;
                _ptr.push_back(_idx);
                for (const auto _next: _graph[_idx]) {
                    if (!_mk[_next]) {
                        _f_dfs(_next, _ptr);
                    }
                }
            };

            _f_dfs(ref.second, _part);
            parts.push_back(_part);
        }
    }

#ifdef DISP_COMPONENT_STA
    auto __f = [&] (const decltype(parts) ve) -> size_t {
        size_t ret = 0;
        for(const auto & v: ve) {
            ret = max(ret, v.size());
        }
        return ret;
    };
    printf("Num. of component: %ld, maximum component size: %ld", parts.size(), __f(parts));

    using size_collector = map<size_t, size_t>;
    size_collector cc;

    auto __f_stat = [&] (const decltype(parts) & ve,  size_collector & col) -> void {
        for(const auto & ref: ve) {
            const size_t ___t = ref.size();
            if (col.find(___t) == col.end()) {
                col.insert({___t, 1});
            } else {
                ++ col[___t];
            }
        }
    };

    auto __f_print = [&] (const size_collector & col) -> void {
        for (const auto & ref: col) {
            printf("|- %5ld-%-5ld\n", ref.first, ref.second);
        }
    };

    __f_stat(parts, cc);
    __f_print(cc);
#endif

#ifdef DISP_COMPONENT_DEGREE
    for(const auto & item: parts) {
        map<size_t, size_t> degree_stat_in, degree_stat_out;
        size_t edge_num = 0, edge_long = 0, edge_short = 0;

        const auto get_out_degree_addr = [&] (size_t _idx) -> size_t {
            const auto & _addr = _vertex_reverse[_idx];
            return long_edge_out.count(_addr) ? long_edge_out.at(_addr).size() : 0 +
                    short_edge_out.count(_addr) ? short_edge_out.at(_addr).size() : 0;
        };
        const auto get_in_degree_addr = [&] (size_t _idx) -> size_t {
            const auto & _addr = _vertex_reverse[_idx];
            return long_edge_in.count(_addr) ? long_edge_in.at(_addr).size() : 0 +
                    short_edge_in.count(_addr) ? short_edge_in.at(_addr).size() : 0;
        };

        for (const auto index: item) {

            const auto & addr = _vertex_reverse[index];
            if (long_edge_out.count(addr)) {
                edge_num += long_edge_out.at(addr).size();
                edge_long += long_edge_out.at(addr).size();
            }
            if (short_edge_out.count(addr)) {
                edge_num += short_edge_out.at(addr).size();
                edge_short += short_edge_out.at(addr).size();
            }
            auto res = get_in_degree_addr(index);
            if (degree_stat_in.count(res)) {
                ++ degree_stat_in[res];
            } else {
                degree_stat_in.insert({res, 1});
            }

            res = get_out_degree_addr(index);
            if (degree_stat_out.count(res)) {
                ++ degree_stat_out[res];
            } else {
                degree_stat_out.insert({res, 1});
            }
        }

        printf("Component size: %4ld.\nDegree out statistic: ", item.size());
        for (const auto & ref: degree_stat_out) {
            printf("[%4ld]:%-3ld ", ref.first, ref.second);
        }
        putchar('\n');
        printf("Degree in statistic: ");
        for (const auto & ref: degree_stat_in) {
            printf("[%4ld]:%-3ld ", ref.first, ref.second);
        }
        putchar('\n');
        printf("Edge Statistic: %ld [EP: %ld, LL:%ld]\n\n", edge_num, edge_short, edge_long);
    }
#endif

    auto ret = make_shared<component>();
    for (const auto & ele: parts) {
        ret->push_back({});
        auto & tar = ret->at(ret->size() - 1);
        for (const auto & ve: ele) {
            tar.push_back(_vertex_reverse[ve]);
        }
    }

#ifdef ADD_GLOBAL_SHORT_CLUSTER
    vector<addr_t> _vertex_glb;
    set_difference(vertex_set_short.cbegin(), vertex_set_short.cend(), 
                   vertex_set_short_reduce.cbegin(), vertex_set_short_reduce.cend(),
                   back_inserter(_vertex_glb));
    set<addr_t> _set_glb(_vertex_glb.cbegin(), _vertex_glb.cend());
    _vertex_glb.clear();
    _vertex_glb.assign(_set_glb.cbegin(), _set_glb.cend());
    ret->push_back(_vertex_glb);
#endif

    LOGF("Identified %ld components on graph.", ret->size());

    __STOP_FTIMER__
    __PRINTF_EXE_TIME__

    return ret;
}


auto traffic_graph::component_select(const shared_ptr<component> p_com) const -> shared_ptr<vector<size_t>> {
    __START_FTIMMER__
    LOGF("Select strong connected conponents.");

    const auto _f_extract_feature_component = [&] (const component::value_type & cp) -> feature_t {
        unordered_set<size_t> _long_index, _short_index, _short_agg_index;
        _acquire_edge_index(cp, _long_index, _short_index);
        size_t byte_ctr_long = 0, byte_ctr_short = 0;
        for (const size_t idx: _long_index) {
            const auto db_ref = p_long_edge->at(idx)->get_length_distribution();
            for (const auto & ref: *db_ref) {
                byte_ctr_long += ref.second;
            }
        }
        for (const size_t idx: _short_index) {
            const auto pk_ref = p_short_edge->at(idx)->get_flow_index(0);
            const auto edge_size = p_short_edge->at(idx)->get_agg_size();
            size_t acc = 0;
            for (const auto p_p: *pk_ref->get_p_packet_p_seq()) {
                acc += p_p->len;
            }
            byte_ctr_short += acc * edge_size;
        }
        return {
            (double) cp.size(),
            (double) _long_index.size(),
            (double) _short_index.size(),
            (double) _short_agg_index.size(),
            (double) byte_ctr_long,
            (double) byte_ctr_short
        };
    };

    const auto _f_trans_armadillo_mat_T = [&] (const vector<feature_t> & mx) -> arma::mat {
            size_t x_len = mx.size();
            size_t y_len = mx[0].size();
            arma::mat mxt(y_len, x_len , arma::fill::randu);
            for (size_t i = 0; i < x_len; i ++) {
                for (size_t j = 0; j < y_len; j ++) {
                    mxt(j, i) = mx[i][j];
                }
            }
            return mxt;
    };

    vector<feature_t> cp_feature;
    for_each(p_com->cbegin(), p_com->cend(), [&] (const component::value_type & cp) -> void {
        cp_feature.push_back(_f_extract_feature_component(cp));
    });
    auto cp_f_mat = _f_trans_armadillo_mat_T(cp_feature);
    mlpack::data::MinMaxScaler scale_cp;
    scale_cp.Fit(cp_f_mat);
    decltype(cp_f_mat) __cp_pre_norm_feature = cp_f_mat;
    scale_cp.Transform(__cp_pre_norm_feature, cp_f_mat);
    
    arma::mat centroids_cp;
    arma::Row<size_t> assignments_cp;
    
#if __has_include(<mlpack/core/distances/lmetric.hpp>)
    mlpack::DBSCAN<> k_cp(uc, vc);
#else
    mlpack::dbscan::DBSCAN<> k_cp(uc, vc);
#endif
    k_cp.Cluster(cp_f_mat, assignments_cp, centroids_cp);

    const auto __get_loss_cp = [&centroids_cp] (const decltype(cp_f_mat.col(0)) & _vec) -> double_t {
        double_t res = HUG;
#if __has_include(<mlpack/core/distances/lmetric.hpp>)
        mlpack::EuclideanDistance euclidean_eval;
#else
        mlpack::metric::EuclideanDistance euclidean_eval;
#endif
        for (size_t i = 0; i < centroids_cp.n_cols; i ++) {
            res = min(res, euclidean_eval.Evaluate(centroids_cp.col(i), _vec) );
        }
        return res;
    };

    vector<pair<double_t, size_t> > loss_vec;
    for (size_t i = 0; i < cp_f_mat.n_cols; i ++) {
        loss_vec.push_back({__get_loss_cp(cp_f_mat.col(i)), i});
    }
    sort(loss_vec.begin(), loss_vec.end(), [&] 
    (decltype(loss_vec)::value_type & a, decltype(loss_vec)::value_type & b) -> bool { return a.first > b.first; });

#ifdef DISP_SELECTED_COMPONENT_STA
    const auto _f_disp_selected_component = [&] (const size_t index) -> void {
        const auto _vec_feature = _f_extract_feature_component(p_com->at(index));
        printf("Seclect Component: size %5d, long edge %5d, short edge %5d (Agg.: %5d).\n",
        (uint32_t) _vec_feature[0],
        (uint32_t) _vec_feature[1],
        (uint32_t) _vec_feature[2],
        (uint32_t) _vec_feature[3]);
    };
#endif

    const auto res_ptr = make_shared<vector<size_t> >();
    for (size_t i = 0; i < ceil(loss_vec.size() * select_ratio); i ++) {
        const auto selected_index = loss_vec[i].second;
        res_ptr->push_back(selected_index);
#ifdef DISP_SELECTED_COMPONENT_STA
        _f_disp_selected_component(selected_index);
#endif
    }
    LOGF("Seclect %ld components from %ld.", res_ptr->size(), loss_vec.size());

    __STOP_FTIMER__
    __PRINTF_EXE_TIME__

    return res_ptr;
}
