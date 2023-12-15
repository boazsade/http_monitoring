#pragma once
#include <cstdint>
#include <string_view>
struct pcap_pkthdr;

namespace tests
{

// for all the packet we have the flowing:
constexpr std::string_view EXPECTED_SOURCE_IP = "10.0.0.8";
constexpr std::string_view EXPECTED_DEST_IP = "62.219.78.157";
constexpr std::uint16_t EXPECTED_SOURCE_PORT = 38854;
constexpr std::uint16_t EXPECTED_DEST_PORT = 80;

constexpr std::string_view EXPECTED_SOURCE_IP_TLS = "10.0.0.8";
constexpr std::string_view EXPECTED_DEST_IP_TLS = "172.217.22.100";
constexpr std::uint16_t EXPECTED_SOURCE_PORT_TLS = 37394;
constexpr std::uint16_t EXPECTED_DEST_PORT_TLS = 443;

using packet_data_t = std::basic_string_view<std::uint8_t>;

auto make_pcap_header(std::uint32_t len) -> pcap_pkthdr;
auto client_connect_packet() -> packet_data_t;
auto server_accept_packet() -> packet_data_t;
auto client_ack_packet() -> packet_data_t;
auto server_ack_packet() -> packet_data_t;
auto client_http_get_packet() -> packet_data_t;
auto server_http_response_http_body() -> packet_data_t;
auto server_http_response_http_headers() -> packet_data_t;
auto client_tcp_close_packet() -> packet_data_t;
auto server_tcp_close_packet() -> packet_data_t;

auto client_connect_with_tls() -> packet_data_t;
auto server_accept_with_tls() -> packet_data_t;
auto client_ack_with_tls() -> packet_data_t;
auto serer_ack_with_tls() -> packet_data_t;
auto client_hello_with_tls() -> packet_data_t;
auto server_hello_with_tls() -> packet_data_t;
auto client_cipher_with_tls() -> packet_data_t;
auto server_app_with_tls() -> packet_data_t;
auto client_app_with_tls() -> packet_data_t;
auto client_close_with_tls() -> packet_data_t;
auto server_close_with_tls() -> packet_data_t;
auto server_app_data_large() -> packet_data_t;
auto traffic_over_vlan() -> packet_data_t;

}   // end of namespace tests