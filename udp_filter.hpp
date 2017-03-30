#ifndef UDP_FILTER
#define UDP_FILTER

#include <stdint.h>
#include <functional>

namespace udp_packet_filter
{

namespace pcap
{
class pcap_file_reader;
}

namespace udp
{

struct udp_packet_data
{
    uint16_t src_port{ 0 };
    uint16_t dst_port{ 0 };
    uint32_t src_ip{ 0 };
    uint32_t dst_ip{ 0 };
    uint16_t payload_len{ 0 };
};

// Reads packets from reader. If packet is udp & pred returns true, callback is called
// Returns number of matched packets
uint64_t filter_udp_packets( pcap::pcap_file_reader& reader,
                             std::function< bool( const udp_packet_data& ) > pred,
                             std::function< void( const udp_packet_data&, const timeval& capture_time ) > callback );

}

}// udp_packet_filter

#endif
