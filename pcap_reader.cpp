#include "pcap_reader.hpp"
#include <array>

namespace udp_packet_filter
{

namespace pcap
{

pcap_file_reader::pcap_file_reader( const std::string& pcap_file_path, const time_precision& prec )
{
    reset( pcap_file_path, prec );
}

pcap_file_reader::pcap_file_reader( pcap_file_reader&& other ) noexcept :
                                    m_pcap_source( std::move( other.m_pcap_source ) ),
                                    m_precision( other.m_precision ),
                                    m_depleted( other.m_depleted )
{
    other.m_depleted = true;
}

pcap_file_reader& pcap_file_reader::operator=( pcap_file_reader&& other ) noexcept
{
    m_pcap_source = std::move( other.m_pcap_source );
    m_precision = other.m_precision;
    m_depleted = other.m_depleted;

    other.m_depleted = true;
}

bool pcap_file_reader::read_next_packet( raw_packet_data& packet )
{
    bool packet_read{ false };

    if( !m_depleted )
    {
        pcap_pkthdr* header{ nullptr };
        int res{ pcap_next_ex( m_pcap_source.get(), &header, &packet.packet ) };

        if( res == 1 )
        {
            packet.timestamp = header->ts;
            packet.len = header->caplen;
            packet_read  = true;
        }
        else if( res == -2 ) // eof
        {
            m_depleted = true;
        }
        else if( res == -1 ) //error
        {
            throw pcap_read_error{ std::string{ "Error getting next packet: " } +
                                   pcap_geterr( m_pcap_source.get() ) };
        }
    }

    return packet_read;
}

void pcap_file_reader::reset( const std::string& pcap_file_path, const time_precision& prec )
{    
    if( pcap_file_path.empty() )
    {
        throw std::invalid_argument{ "File path is empty" };
    }   

    std::array< char, PCAP_ERRBUF_SIZE > error;
    m_pcap_source.reset( pcap_open_offline_with_tstamp_precision( pcap_file_path.c_str(),
                                                                  static_cast< uint >( prec ),
                                                                  error.data() ) );

    if( !m_pcap_source )
    {
        m_depleted = true;
        throw source_open_error{ error.data() };
    }

    m_precision = prec;
    m_depleted = false;
}

auto pcap_file_reader::precision() const noexcept -> const time_precision&
{
    return m_precision;
}

bool pcap_file_reader::is_depleted() const noexcept
{
    return m_depleted;
}

}// pcap

}// udp_analyzer
