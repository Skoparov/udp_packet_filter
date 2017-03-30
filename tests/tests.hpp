#ifndef TESTS
#define TESTS

#include <functional>

#include "test_helpers.hpp"

#include "../helpers.hpp"
#include "../udp_filter.cpp"
#include "../pcap_reader.cpp"

using namespace udp_packet_filter;

namespace tests
{

void test_valiate_ip()
{
    using namespace udp_packet_filter::helpers;
    TEST_ASSERT( validate_ip( "192.168.0.1" ),   ERR_MSG( TEST_NAME, "Valid ip not recognized" ) );
    TEST_ASSERT( !validate_ip( "192..168.0.1" ), ERR_MSG( TEST_NAME, "Invalid ip 1 accepted" ) );
    TEST_ASSERT( !validate_ip( "256.168.0.1" ),  ERR_MSG( TEST_NAME, "Invalid ip 2 accepted" ) );
}

void test_stous()
{
    using namespace udp_packet_filter::helpers;
    TEST_EXEC_FUNC( TEST_NAME, THROW_COND::SHOULD_NOT_THROW, stous, "255" );
    TEST_EXEC_FUNC( TEST_NAME, THROW_COND::SHOULD_THROW, stous, "255000" );
    TEST_EXEC_FUNC( TEST_NAME, THROW_COND::SHOULD_THROW, stous, "-1" );
    TEST_EXEC_FUNC( TEST_NAME, THROW_COND::SHOULD_THROW, stous, "asd" );
}

void test_pcap_file_reader( const std::string& data2_pcap_path )
{
    using namespace udp_packet_filter::pcap;

    pcap_file_reader r;

    try
    {
        pcap_file_reader r1{ data2_pcap_path, pcap_file_reader::time_precision::micro };
        r = std::move( r1 );
    }
    catch( const std::exception& e )
    {
        throw test_error{ ERR_MSG( TEST_NAME, e.what() ) };
    }

    // Check for constructor-opened read and read after reset
    for( int i{ 0 }; i < 2; ++i )
    {
        TEST_ASSERT( r.precision() == pcap_file_reader::time_precision::micro,
                     ERR_MSG( TEST_NAME, "Invalid recision" ) );

        TEST_ASSERT( !r.is_depleted(), ERR_MSG( TEST_NAME, "Depleted before read" ) );

        raw_packet_data raw_data;
        uint64_t packets_read{ 0 };

        auto read_packet_func = [ &r, &raw_data ]()->bool{ return r.read_next_packet( raw_data ); };
        while( TEST_EXEC_FUNC_RESULT( TEST_NAME, THROW_COND::SHOULD_NOT_THROW, read_packet_func ) )
        {
            ++packets_read;
        }

        TEST_ASSERT( packets_read == 1711, ERR_MSG( TEST_NAME, "Invalid number of read packets" ) );
        TEST_ASSERT( r.is_depleted(), ERR_MSG( TEST_NAME, "Not depleted before read" ) );

        if( i == 0 ) // reset after first iteration
        {
            r.reset( data2_pcap_path, pcap_file_reader::time_precision::micro );
        }
    }
}

void test_udp_filter( const std::string& data2_pcap_path )
{
    using namespace udp_packet_filter::udp;
    using namespace udp_packet_filter::pcap;

    uint64_t packets_matched{ 0 };

    uint16_t dst_port{ 53 };
    uint32_t dst_ip{ inet_addr( "192.168.88.1" ) };

    auto pred = [ dst_ip, dst_port ]( const udp::udp_packet_data& data ) -> bool
    {
       if( ( dst_port && data.dst_port != dst_port ) ||
           ( dst_ip && data.dst_ip != dst_ip ) )
        {
            return false;
        }

        return true;
    };

    pcap_file_reader r{ data2_pcap_path, pcap_file_reader::time_precision::micro };

    // Callback called for the packets meeting the conditions
    auto callback = [ &packets_matched ]( const udp::udp_packet_data& data, const timeval& time )
    {
        ++packets_matched;
    };

    uint64_t packets_returned{
        TEST_EXEC_FUNC_RESULT( TEST_NAME, THROW_COND::SHOULD_NOT_THROW, filter_udp_packets, r, pred, callback ) };

    TEST_ASSERT( packets_matched == packets_returned,
                 ERR_MSG( TEST_NAME, "Number of packets matched != number of packets returned" ) );

    TEST_ASSERT( packets_matched == 9, ERR_MSG( TEST_NAME, "Invalid umber of matched packets" ) );
}

void run_all_tests( const std::string& data2_pcap_path )
{
    try
    {
        test_valiate_ip();
        test_stous();
        test_pcap_file_reader( data2_pcap_path );
        test_udp_filter( data2_pcap_path );
    }
    catch( const std::exception& e )
    {
        std::cout << e.what() << std::endl;
        return;
    }

    std::cout<<"Runtime tests ok\n";
}

}

#endif
