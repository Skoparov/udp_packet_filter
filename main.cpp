#include <iostream>
#include <iomanip>
#include <limits>

#include "pcap_reader.hpp"
#include "udp_filter.hpp"
#include "helpers.hpp"

struct params
{
    uint16_t dst_port{ 0 };
    uint32_t dst_ip{ 0 };
    std::string pcap_path;
};

void parse_args( int argc, char** argv, params& p )
{
    using namespace udp_packet_filter::helpers;

    for( int pos{ 1 }; pos < argc; ++pos )
    {
        std::string key{ argv[ pos ] };

        if( key == "-a" && pos != argc - 1 )
        {
            if( p.dst_ip != 0 )
            {
                throw std::invalid_argument{ "Multiple adresses specified" };
            }

            std::string ip{ argv[ ++pos ] };
            if( !validate_ip( ip ) )
            {
                throw std::invalid_argument{ "Invalid ip" };
            }

            p.dst_ip = inet_addr( ip.c_str() );
        }
        else if( key == "-p" && pos != argc - 1 )
        {
            if( p.dst_port != 0 )
            {
                throw std::invalid_argument{ "Multiple ports specified" };
            }

            try
            {
                 p.dst_port = stous( argv[ ++pos ] );
            }
            catch( ... )
            {
                throw std::invalid_argument{ "Invalid port" };
            }
        }
        else if( pos == argc - 1 )
        {
            p.pcap_path = argv[ pos ];
        }
        else
        {
            throw std::invalid_argument{ "Unrecognized argument" };
        }
    }

    if( p.pcap_path.empty() )
    {
        throw std::invalid_argument{ "No pcap file specified" };
    }
}

int main( int argc, char** argv )
{       
    using namespace udp_packet_filter;

    params p;

    try
    {
        parse_args( argc, argv,p );
    }
    catch( const std::invalid_argument& e )
    {
        std::cout<< e.what() << "\n"
                 << "Usage: -p DST_PORT -a DST_IP PATH_TO_PCAP\n";

        return 1;
    }

    uint32_t dst_ip{ p.dst_ip };
    uint16_t dst_port{ p.dst_port };

    // Predicate checking if a packet matches the conditions
    auto pred = [ dst_ip, dst_port ]( const udp::udp_packet_data& data )-> bool
    {
       if( ( dst_port && data.dst_port != dst_port ) ||
           ( dst_ip && data.dst_ip != dst_ip ) )
        {
            return false;
        }

        return true;
    };

    // Callback called for the packets meeting the conditions
    auto callback = []( const udp::udp_packet_data& data, const timeval& time )
    {
        // Format timeval into string
        time_t ttime{ static_cast< time_t >( time.tv_sec ) };
        std::array< char, 20 > buff;
        strftime( buff.data(), buff.size(), "%Y-%m-%d %H:%M:%S", std::localtime( &ttime ) );

        // Print packet info
        std::cout << std::left
                  << buff.data() << ":" << std::setw( 7 ) << std::to_string( time.tv_usec ) // time
                  << std::setw( 16 ) << inet_ntoa( in_addr{ data.dst_ip } ) // dst ip
                  << std::setw( 8 ) << std::to_string( data.dst_port ) // dst port
                  << std::to_string( data.payload_len ) << std::endl; //payload
    };

    try
    {
        std::cout << std::left
                  << std::setw( 27 ) << "Time"
                  << std::setw( 16 ) << "DstIp"
                  << std::setw( 8 ) << "DstPort"
                  << "PayloadLen"
                  << "\n-------------------------------------------------------------\n";

        pcap::pcap_file_reader r{ p.pcap_path, pcap::pcap_file_reader::time_precision::micro };
        uint64_t total_matched{ udp::filter_udp_packets( r, pred, callback ) };

        std::cout << "-------------------------------------------------------------\n"
                     "Total packets: " << total_matched << std::endl;
    }
    catch( const std::exception& e )
    {
        std::cout << e.what() << std::endl;
        return 1;
    }

    return 0;
}
