# Udp Packet Filter

Reads a pcap file and prints udp packets meeting the conditions specified in args. Dependencies: ```libpcap```
```
Usage: ./udp_packet_filter -p DST_PORT -a DST_IP PATH_TO_PCAP
```
Only ```PATH_TO_PCAP``` argument is mandatory.

---------------------------------------------

#Tests

```
Usage: ./udp_packet_filter_tests PATH_TO_DATA2.PCAP
```

where PATH_TO_DATA2.PCAP is a path to data2.pcap file from ```tests``` directory.

