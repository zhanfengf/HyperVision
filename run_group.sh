groups=(bruteforce lrscan malware misc web)

bruteforce=(
    "charrdos"
    "cldaprdos"
    "dnsrdos"
    "dnsscan"
    "httpscan"
    "httpsscan"
    "icmpscan"
    "icmpsdos"
    "memcachedrdos"
    "ntprdos"
    "ntpscan"
    "riprdos"
    "rstsdos"
    "sqlscan"
    "ssdprdos"
    "sshscan"
    "synsdos"
    "udpsdos"
)

lrscan=(
    "dns_lrscan"
    "http_lrscan"
    "icmp_lrscan"
    "netbios_lrscan"
    "rdp_lrscan"
    "smtp_lrscan"
    "snmp_lrscan"
    "ssh_lrscan"
    "telnet_lrscan"
    "vlc_lrscan"
)

malware=(
    "adload"
    "bitcoinminer"
    "ccleaner"
    "coinminer"
    "dridex"
    "emotet"
    "feiwo"
    "koler"
    "magic"
    "mazarbot"
    "mobidash"
    "penetho"
    "plankton"
    "ransombo"
    "sality"
    "snojan"
    "svpeng"
    "thbot"
    "trickbot"
    "trickster"
    "trojanminer"
    "wannalocker"
    "webcompanion"
    "zsone"
)

misc=(
    "sshpwdsm"
    "sshpwdmd"
    "sshpwdla"
    "telnetpwdsm"
    "telnetpwdmd"
    "telnetpwdla"
    "spam1"
    "spam50"
    "spam100"
    "crossfiresm"
    "crossfiremd"
    "crossfirela"
    "lrtcpdos02"
    "lrtcpdos05"
    "lrtcpdos10"
    "ackport"
    "ipidaddr"
    "ipidport"
)

web=(
    "agentinject"
    "codeinject"
    "csfr"
    "oracle"
    "paraminject"
    "persistence"
    "scrapy"
    "sslscan"
    "webshell"
    "xss"
)

rm ../temp/*
group=$1
echo group $group
declare -n ref=$group
for item in ${ref[*]}
do
    cd ..
    rm data/*
    echo $(date +"%Y-%m-%d %H:%M:%S") tar -xzf hypervision-dataset.tar.gz data/$item.{data,label}
    tar -xzf hypervision-dataset.tar.gz data/$item.{data,label}
    cd build

    echo $(date +"%Y-%m-%d %H:%M:%S") ./HyperVision -config ../configuration/$group/${item}.json
    ./HyperVision -config ../configuration/$group/${item}.json > ../cache/${item}.log
done
cd ../result_analyze
./batch_analyzer.py -g ${group%%force} # inconsistent naming of group!
cat ./log/${group%%force}/*.log | grep '\(^\[\|AU_ROC\)'
cd ../build
