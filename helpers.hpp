#ifndef HELPERS
#define HELPERS

#include <limits>
#include <stdexcept>
#include <arpa/inet.h>

namespace udp_packet_filter
{

namespace helpers
{

bool validate_ip( const std::string& ip )
{
    struct sockaddr_in sa;
    int result{ inet_pton( AF_INET, ip.c_str(), &( sa.sin_addr ) ) };
    return ( result != 0 );
}

uint16_t stous( const std::string& num )
{
    int port{ std::stoi( num.c_str() ) };

    if( port < 0 || port > std::numeric_limits< uint16_t >::max() )
    {
        throw std::invalid_argument{ "Conversion failed" };
    }

    return port;
}

}

}

#endif
