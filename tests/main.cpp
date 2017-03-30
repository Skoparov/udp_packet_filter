#include <iostream>
#include "tests.hpp"

int main( int argc, char** argv )
{
    if( argc != 2 )
    {
        std::cout << "Usage: ./udp_packet_filter_tests data2.pcap";
        return 1;
    }

    std::string data2_pcap_path{ argv[ 1 ] };

    tests::run_all_tests( data2_pcap_path );
    return 0;
}
