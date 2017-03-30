#ifndef PCAP_READER
#define PCAP_READER

#include <memory>
#include <string>
#include <stdexcept>

#include <pcap.h>

namespace udp_packet_filter
{

namespace pcap
{

struct raw_packet_data
{
    timeval timestamp;
    const u_char* packet{ nullptr };
    uint32_t len{ 0 };
};

class pcap_file_reader
{
public:
    enum class time_precision : uint{ micro, nano };

public:
    pcap_file_reader() = default;
    pcap_file_reader( const std::string& pcap_file_path, const time_precision& prec = time_precision::micro );
    pcap_file_reader( const pcap_file_reader& ) = delete;
    pcap_file_reader& operator=( const pcap_file_reader& ) = delete;
    pcap_file_reader( pcap_file_reader&& ) noexcept;
    pcap_file_reader& operator=( pcap_file_reader&& ) noexcept;

    bool read_next_packet( raw_packet_data& packet );
    void reset( const std::string& pcap_file_path, const time_precision& prec = time_precision::micro );

    const time_precision& precision() const noexcept;
    bool is_depleted() const noexcept;

private:
    bool m_depleted{ false };
    time_precision m_precision{ time_precision::micro };
    std::unique_ptr< pcap_t, void(*)( pcap_t* ) > m_pcap_source{ nullptr, pcap_close };
};

// Thrown if pcap_file_reader is unable to open the file
class source_open_error : public std::runtime_error
{ using std::runtime_error::runtime_error; };

// Thrown if error occures during packet reading
class pcap_read_error : public std::runtime_error
{ using std::runtime_error::runtime_error; };

}// pcap

}// udp_analyzer

#endif
