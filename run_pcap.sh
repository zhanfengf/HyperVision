echo Backup pcap.pcap to pcap-backup.pcap
mv pcap.pcap pcap-backup.pcap
wget -O pcap.pcap $1
echo Analyzing $1
./HyperVision -config ../configuration/pcap.json

