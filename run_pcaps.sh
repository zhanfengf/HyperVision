cat ../pcap.txt | xargs -n 1 -I '{}' bash ../run_pcap.sh '{}'
