#include "udp_filter.hpp"

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>

#include "pcap_reader.hpp"

namespace udp_packet_filter
{

namespace udp
{

namespace details
{

struct udp_header
{
    u_short	src_port{ 0 };
    u_short	dst_port{ 0 };
    u_short	payload_len{ 0 };
    u_short	checksum{ 0 };
};

bool check_and_get_udp_data( udp_packet_data& data, const u_char* packet, uint32_t packet_len )
{
    if( packet_len < sizeof( ether_header ) + sizeof( ip ) )
    {
        return false;
    }

    packet += sizeof( ether_header );
    packet_len -= sizeof( ether_header );

    const ip* ip_ptr{ reinterpret_cast< const ip* >( packet ) };
    int ip_header_len{ ip_ptr->ip_hl * 4 };	/* measured in 4 byte words */

    if( packet_len < ip_header_len || ip_ptr->ip_p != IPPROTO_UDP )
    {
        return false;
    }

    packet += ip_header_len;
    packet_len -= ip_header_len;

    if( packet_len < sizeof( details::udp_header ) )
    {
        return false;
    }

    const details::udp_header* udp_hdp{ reinterpret_cast< const details::udp_header* >( packet ) };

    data.src_port = ntohs( udp_hdp->src_port );
    data.dst_port = ntohs( udp_hdp->dst_port );
    data.src_ip = ip_ptr->ip_src.s_addr;
    data.dst_ip = ip_ptr->ip_dst.s_addr;
    data.payload_len = ntohs( udp_hdp->payload_len ) - sizeof( udp_header );
}

}// details

uint64_t filter_udp_packets( pcap::pcap_file_reader& reader,
                         std::function< bool( const udp_packet_data& ) > pred,
                         std::function< void( const udp_packet_data&, const timeval& ) > callback )
{
    pcap::raw_packet_data raw_data;
    udp_packet_data udp_data;
    uint64_t packets_accepted{ 0 };

    while( reader.read_next_packet( raw_data ) )
    {
        if( details::check_and_get_udp_data( udp_data, raw_data.packet, raw_data.len ) &&
            pred( udp_data ) )
        {
            ++packets_accepted;
            callback( udp_data, raw_data.timestamp );
        }
    }

    return packets_accepted;
}

}// udp

}// udp_analyzer
