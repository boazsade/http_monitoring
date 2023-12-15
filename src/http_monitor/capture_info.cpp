#include "capture_info.h"
#include "Log/logging.h"
#include "http_match.h"
#include <iostream>
#include <pcap.h>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <iterator>
#include <cstring>
#include <string_view>
#include <numeric>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <time.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>

namespace monitor
{
    using namespace std::string_literals;

namespace
{

constexpr std::uint64_t SEC2MICRO = 1000 * 1000;
constexpr std::uint32_t OCTETS_2_BYTES = 4;

#pragma pack(push, 1)
struct tls_header
{
    std::uint8_t type = 0;
    std::uint8_t major_version = 0;
    std::uint8_t minor_version = 0;
    std::uint16_t length = 0;

    constexpr tls_header() = default;
    constexpr tls_header(const std::uint8_t* raw) : type(*raw), 
        major_version(*(raw + sizeof(std::uint8_t))), minor_version(*(raw + (2 * sizeof(std::uint8_t)))),
        length(*(const std::uint16_t*)(raw + (sizeof(std::uint8_t) + sizeof(std::uint16_t)))) {

    }
};
#pragma pack(pop)

enum tls_type : std::uint8_t {
    CHANGE_CIPHER = 0x14,
    TLS_ALERT = 0x15,
    HANDSHAKE = 0x16,
    APPLICATION = 0x17,
    HEARTBEAT = 0x18
};

auto operator << (std::ostream& os, tls_type t) -> std::ostream& {
    switch (t) {
        case tls_type::APPLICATION:
            return os << "application message";
        case tls_type::CHANGE_CIPHER:
            return os << "cipher exchange message";
        case tls_type::HANDSHAKE:
            return os << "handshake message";
        case tls_type::HEARTBEAT:
            return os << "heartbeat message";
        case tls_type::TLS_ALERT:
            return os << "alert message";
        default:
            return os << "invalid message type: " << (unsigned int)t;
    }
}

enum tls_version_major : std::uint8_t {
    SSL_2 = 2,                 // older versions
    OTHERS_VERSIONS = 3        // all versions for TLS/SSL are the same
};

auto operator << (std::ostream& os, tls_version_major v) -> std::ostream& {
    switch (v) {
        case tls_version_major::SSL_2:
            return os << "SSL2";
        case tls_version_major::OTHERS_VERSIONS:
            return os << "SSL3/TLS";
        default:
            return os << "unknown version: " << (unsigned int)v;
    }
}

enum tls_version_minor : std::uint8_t {
    SSL_3 = 0,
    TLS_1 = 1,
    TLS_1_1 = 2,
    TLS_1_2 = 3,
    TLS_1_3 = 4
};

auto operator << (std::ostream& os, tls_version_minor v) -> std::ostream& {
    switch (v) {
        case tls_version_minor::SSL_3:
            return os << "SSL v3";
        case tls_version_minor::TLS_1:
            return os << "TLS 1";
        case tls_version_minor::TLS_1_1:
            return os << "TLS 1.1";
        case tls_version_minor::TLS_1_2:
            return os << "TLS 1.2";
        case tls_version_minor::TLS_1_3:
            return os << "TLS 1.3";
        default:
            return os << "invalid version " << (unsigned int)v;
    }
}

enum tls_handshake_types : std::uint8_t {
    HELLO_REQUEST = 0x0,
    CLIENT_HELLO = 0x1,
    SERVER_HELLO = 0x2,
    NEW_TICKET = 0x4,
    EXTENTION = 0x8,
    CERT = 0xB,
    SERVER_KEY_EXCHANGE = 0xC,
    CERTIFICATE_REQUEST = 0xD,
    SERVER_HELLO_DONE = 0xE,
    CERTIFICATE_VALID = 0xF,
    CLIENT_KEY_EXCHANGE = 0x10,
    FINISHED = 0x14
};

auto operator << (std::ostream& os, tls_handshake_types ht) -> std::ostream& {
    switch (ht) {
        case tls_handshake_types::CERT:
            return os << "CERT";
        case tls_handshake_types::CERTIFICATE_REQUEST:
            return os << "cert request";
        case tls_handshake_types::CERTIFICATE_VALID:
            return os << "cer valid";
        case tls_handshake_types::CLIENT_HELLO:
            return os <<"client hello";
        case tls_handshake_types::CLIENT_KEY_EXCHANGE:
            return os << "key exchange";
        case tls_handshake_types::EXTENTION:
            return os << "extention";
        case tls_handshake_types::FINISHED:
            return os << "finished";
        case tls_handshake_types::HELLO_REQUEST:
            return os << "hello request";
        case tls_handshake_types::NEW_TICKET:
            return os << "new ticket";
        case tls_handshake_types::SERVER_HELLO:
            return os << "server hello";
        case tls_handshake_types::SERVER_HELLO_DONE:
            return os << "server hello done";
        case tls_handshake_types::SERVER_KEY_EXCHANGE:
            return os << "server key exchange";
        default:
            return os << "invalid handshake type " << (unsigned int) ht;
    }
}

constexpr std::uint16_t first_nibble = 8;
constexpr std::uint16_t nibble_mask = 0x00ff;

constexpr auto swap_bytes(std::uint16_t from) -> std::uint16_t {
    return ((from << first_nibble) & nibble_mask) | ((from >> first_nibble) & nibble_mask);
}

#pragma pack(push, 1)
struct tls_handshake
{
    static constexpr std::uint8_t expected_type = tls_type::HANDSHAKE;

    std::uint8_t type = 0;      // tls_handshake_types
    std::uint8_t len_msb = 0;   // len is 24 bits
    std::uint16_t len_lsb = 0;


    constexpr tls_handshake() = default;
    constexpr tls_handshake(const std::uint8_t* raw) : type{*raw},
                                                      len_msb{*(raw + sizeof(type))},
                                                      len_lsb(swap_bytes(*reinterpret_cast<const std::uint16_t*>(raw + sizeof(type) + sizeof(len_msb)))) {

    }
};
#pragma pack(pop)

struct tls_change_cipher
{

    static constexpr std::uint8_t expected_type = tls_type::CHANGE_CIPHER;

    std::uint8_t spec = 0;

    constexpr tls_change_cipher() = default;
    constexpr tls_change_cipher(const std::uint8_t* raw) : spec{*raw} {

    }
};

constexpr auto valid(tls_change_cipher cs) -> bool {
    return cs.spec == 1;        // see https://en.wikipedia.org/wiki/Transport_Layer_Security
}

auto operator << (std::ostream& os, tls_change_cipher cc) -> std::ostream& {
    return os << "spec: " << (unsigned short)cc.spec;
}

enum tls_alert_level : std::uint8_t {
    TLS_WARNING_LEVEL = 1,
    TLS_FATAL_LEVEL = 2
};

auto operator << (std::ostream& os, tls_alert_level l) -> std::ostream& {
    switch (l) {
        case tls_alert_level::TLS_FATAL_LEVEL:
            return os << "FATAL";
        case tls_alert_level::TLS_WARNING_LEVEL:
            return os << "warning";
        default:
            return os <<  "unkown alert level " << (unsigned int)l;
    }
}

#pragma pack(push, 1)
struct tls_alert
{
    static constexpr std::uint8_t expected_type  = tls_type::TLS_ALERT;

    std::uint8_t level = 0;     // tls_alert_level
    std::uint8_t description = 0;

    constexpr tls_alert() = default;
    constexpr tls_alert(const std::uint8_t* raw) : level{*raw}, description{*(raw + sizeof(level))} {

    }
};
#pragma pack(pop)

constexpr auto valid(tls_alert alert) -> bool {
    // list of invalid values for alert description -> https://en.wikipedia.org/wiki/Transport_Layer_Security
    constexpr std::uint8_t NO_APP_PROTOCOL = 120;
    constexpr std::uint8_t NO_APP_PROTOCOL2 = 255;

    constexpr std::uint8_t invalid_descriptions_values[] = {
        1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13, 14, 15, 16, 17, 18, 19,
        23, 24, 25, 26, 27, 28, 29,
        31, 32, 33, 34, 35, 36, 37, 38, 39,
        52, 53, 54, 55, 56, 57, 58, 59,
        61, 62, 63, 64, 65, 66, 67, 68, 69,
        72, 73, 74, 75, 76, 77, 78, 79,
        81, 82, 83, 84, 85, 87, 88, 89, 91,
        92, 93, 94, 95, 96, 97, 98, 99,
        101, 102, 103, 104, 105, 106, 107, 108, 109,
        117, 118, 119
    };

    if (alert.level != tls_alert_level::TLS_FATAL_LEVEL && alert.level != tls_alert_level::TLS_WARNING_LEVEL) {
        return false;
    }
    if (alert.description == NO_APP_PROTOCOL || alert.description == NO_APP_PROTOCOL2) {
        return true;
    }
    return !std::any_of(std::begin(invalid_descriptions_values), std::end(invalid_descriptions_values), [desc = alert.description] (std::uint8_t d) {
        return desc == d;
    });
}

auto operator << (std::ostream& os, tls_alert a) -> std::ostream& {
    if (valid(a)) {
        return os << "level: " << static_cast<tls_alert_level>(a.level) << ", description: " << (std::uint16_t)a.description;
    }
    return os << "not TLS alert message [" << static_cast<std::uint16_t>(a.level) << ", " << static_cast<std::uint16_t>(a.description) << "]";
}

// we don't have match to do in this case..
struct tls_application
{
    static constexpr std::uint8_t expected_type = tls_type::APPLICATION;

    constexpr tls_application() = default;
};

constexpr auto valid(tls_application) -> bool {
    return true;    // we cannot really validate
}

// again not match is here
struct tls_heartbeat
{
    static constexpr std::uint8_t expected_type = tls_type::HEARTBEAT;

    constexpr tls_heartbeat() = default;
};

constexpr auto valid(tls_heartbeat) -> bool {
    return true;    // we cannot really validate
}

constexpr auto is_handshake(tls_header hs) -> bool {
    return hs.type == tls_handshake::expected_type;
}

constexpr auto is_application(tls_header hs) -> bool {
    return hs.type == tls_application::expected_type;
}

constexpr auto is_alert(tls_header hs) -> bool {
    return hs.type == tls_alert::expected_type;
}

constexpr auto is_heartbeat(tls_header hs) -> bool {
    return hs.type == tls_heartbeat::expected_type;
}

constexpr auto is_cipher_change(tls_header hs) -> bool {
    return hs.type == tls_change_cipher::expected_type;
}

inline auto valid_type(tls_header hs) -> bool {
    static const decltype(is_application)* checkers[] = {
        is_handshake, is_application, is_alert, is_heartbeat, is_cipher_change
    };
    return std::any_of(std::begin(checkers), std::end(checkers), [hs] (auto&& c) {
        return c(hs);
    });
}

constexpr auto valid_version(tls_header hdr) -> bool {
    constexpr tls_version_minor versions[] = {
        tls_version_minor::SSL_3,
        tls_version_minor::TLS_1,
        tls_version_minor::TLS_1_1,
        tls_version_minor::TLS_1_2,
        tls_version_minor::TLS_1_3
    };

    if (hdr.major_version == tls_version_major::OTHERS_VERSIONS || hdr.major_version == tls_version_major::SSL_2) {
        return std::any_of(std::begin(versions), std::end(versions), [hdr](auto v) {
            return v == hdr.minor_version;
        });
    }
    return false;
}

constexpr auto valid(tls_header hs) -> bool {
    return valid_version(hs) && valid_type(hs)  && hs.length > 0;
}

constexpr auto valid(tls_handshake hs) -> bool {
    switch (hs.type) {
        case tls_handshake_types::HELLO_REQUEST:
        case tls_handshake_types::CERT:
        case tls_handshake_types::CERTIFICATE_REQUEST:
        case tls_handshake_types::CERTIFICATE_VALID:
        case tls_handshake_types::CLIENT_HELLO:
        case tls_handshake_types::CLIENT_KEY_EXCHANGE:
        case tls_handshake_types::EXTENTION:
        case tls_handshake_types::FINISHED:
        case tls_handshake_types::NEW_TICKET:
        case tls_handshake_types::SERVER_HELLO:
        case tls_handshake_types::SERVER_HELLO_DONE:
        case tls_handshake_types::SERVER_KEY_EXCHANGE:
            return true;
        default:
            return false;
    }
}

auto operator << (std::ostream& os, tls_header hdr) -> std::ostream& {
    if (valid(hdr)) {
        return os << static_cast<tls_type>(hdr.type) << ", version:[" << static_cast<tls_version_major>(hdr.major_version) << ":" << static_cast<tls_version_minor>(hdr.minor_version) <<", length " << hdr.length;
    } else {
        return os << "this is not TLS message: type: " << (unsigned short)hdr.type <<", version major: " << (unsigned short)hdr.major_version << ", minor " << (unsigned short)hdr.minor_version;
    }
}

auto to_string(tls_header header) -> std::string {
    std::ostringstream p;
    p << header;
    return p.str();
}

auto operator << (std::ostream& os, tls_handshake hs) -> std::ostream& {
    if (valid(hs)) {
        return os << "TLS handshake message: " << static_cast<tls_handshake_types>(hs.type) << ", length " << hs.len_lsb;
    }
    return os << "not TLS handshake message: " << static_cast<std::uint16_t>(hs.type);
}

using tls_payloads = std::variant<tls_handshake, tls_alert, tls_application, tls_heartbeat, tls_change_cipher>;

auto try_from(const data_flow::application_data& from) -> result<tls_payloads, std::string> {
    constexpr auto MIN_PAYLOAD_SIZE = sizeof(tls_header);

    if (from.size() < MIN_PAYLOAD_SIZE) {
        return failed("no payload, this cannot be TLS message"s);
    }
    tls_header header{from.data()};
    if (!valid(header)) {
        return failed("this is not valid TLS header: "s + to_string(header));
    }
    const auto start = from.data() + sizeof(tls_header);
    if (is_handshake(header) && from.size() > sizeof(tls_handshake) + MIN_PAYLOAD_SIZE) {
        return ok(tls_payloads{tls_handshake{start}});
    }
    if (is_alert(header) && from.size() >= (sizeof(tls_alert) + MIN_PAYLOAD_SIZE)) {
        return ok(tls_payloads{tls_alert{start}});
    }
    if (is_application(header) && from.size() > (sizeof(tls_application) + MIN_PAYLOAD_SIZE)) {
        return ok(tls_payloads{tls_application{}});
    }
    if (is_heartbeat(header) && from.size() >= (sizeof(tls_header) + MIN_PAYLOAD_SIZE)) {
        return ok(tls_payloads{tls_heartbeat{}});
    }
    if (is_cipher_change(header) && from.size() >= (sizeof(tls_change_cipher) + MIN_PAYLOAD_SIZE)) {
        return ok(tls_payloads{tls_change_cipher(start)});
    }
    return failed("invalid length for TLS message or unsupported type: "s  + to_string(header));
}

auto valid(tls_payloads&& tls_msg) -> bool {
    return std::visit([] (auto&& msg) {
        return valid(msg);
    }, tls_msg);
}

#ifdef SUPPORT_IPV6
auto print_flow_payload(const data_flow::application_data& data, std::ostream& os) -> void {
    if (!data.empty()) {
        os << "\n\t\tpayload start: ";
        std::string_view s((const char*)&data[0], std::min(data.size(), 80lu));
        os << s << "\n";
    }
}

auto make_ipv6_from_network(const std::uint8_t* start) -> IPv6::address_type {
    IPv6::address_type store;
    std::copy(start, start + IPv6::address_len, store.begin());
    return store;
}

// code was taken from https://github.com/seladb/PcapPlusPlus
struct ip6_hdr {
#if (BYTE_ORDER == LITTLE_ENDIAN)
	/** Traffic class */
	uint8_t trafficClass:4,
	/** IP version number, has the value of 6 for IPv6 */
	version:4;
#else
		/** IP version number, has the value of 6 for IPv6 */
	uint8_t version:4,
		/** Traffic class */
	trafficClass:4;
#endif  // (BYTE_ORDER == LITTLE_ENDIAN)
		/** Flow label */
	uint8_t flowLabel[3];
		/** The size of the payload in octets, including any extension headers */
	uint16_t payloadLength;
		/** Specifies the type of the next header (protocol). Must be one of ::IPProtocolTypes */
	uint8_t nextHeader;
		/** Replaces the time to live field of IPv4 */
	uint8_t hopLimit;
		/** Source address */
	uint8_t ipSrc[16];
		/** Destination address */
	uint8_t ipDst[16];
};
#endif // SUPPORT_IPV6

constexpr auto no_data(const TCP& tcp) -> bool {
    return tcp.fin_sent() || tcp.syn_packet() || tcp.is_reseting();
}

auto parse_tcp_packet(const std::uint8_t* tcp_header, const std::uint8_t* packets, std::uint32_t cur_len, 
    std::uint32_t ip_header_length, std::size_t ether_len) -> std::tuple<std::optional<TCP>, data_flow::application_data> {

    auto tcp_hdr = (const struct tcphdr*)tcp_header;
    auto tcp_header_length = tcp_hdr->doff * OCTETS_2_BYTES;
    auto tcp_layer = from_capture(tcp_hdr);     // will use for the return value

    // Add up all the header sizes to find the payload offset 
    auto total_headers_size = ether_len + ip_header_length + tcp_header_length;
    if (total_headers_size > cur_len) {
        return {std::nullopt, {}};
    }
    auto payload_length = no_data(*tcp_layer) ? 0 :  cur_len - total_headers_size;
        
    auto payload = packets + total_headers_size;

    if (payload_length > 0) {
        return {tcp_layer, data_flow::application_data(payload, payload_length)};
    } else {
        return {tcp_layer, {}};
    }
}


}   // end of local namespace

auto to_string(IPv4 ip) -> std::string {
    char str[INET_ADDRSTRLEN];
    struct sockaddr_in sa;
    sa.sin_addr.s_addr = ip.address;
    inet_ntop(AF_INET, &(sa.sin_addr), str, INET_ADDRSTRLEN);
    return str;
}
auto operator << (std::ostream& os, IPv4 address) -> std::ostream& {
    return os<<"IPv4 address: "<<to_string(address);
}

auto type_from_capture(const std::basic_string_view<std::uint8_t> cap, std::size_t offset) -> ethernet_type {
    constexpr std::size_t START_FROM_TYPE = 2;
    constexpr std::size_t END_FROM_TYPE = 1;

    if (cap.size() < offset) {
        throw std::runtime_error{"invalid length for packet less than minimum size"};
    }

    auto ether_type = ((int)(cap[offset - START_FROM_TYPE]) << 8) | (int)cap[offset - END_FROM_TYPE];
    switch (ether_type) {
	case ETHERTYPE_IP:
        return ethernet_type::ETHER_IPv4;
	case ETHERTYPE_IPV6:
        return ethernet_type::ETHER_IPv6;
    case ETHERTYPE_VLAN:
        return ethernet_type::ETHER_VLAN;
	default:
        return ethernet_type::ETHER_UNKOWN;
    }
}

auto to_string(IPv6 ip) -> std::string {
    char str[INET6_ADDRSTRLEN];
    if (inet_ntop(AF_INET6, &ip.address[0], str, INET6_ADDRSTRLEN) == 0) {
        return str;
    }
    return {};
}

auto operator << (std::ostream& os, IPv6 address) -> std::ostream& {
    return os<<"IPv6 address: "<<to_string(address);
}

auto to_string(IPv4_flow flow) -> std::string {
    return "{" + to_string(flow.source) + " -> " + to_string(flow.dest) + "}";
}

auto operator << (std::ostream& os, IPv4_flow address) -> std::ostream& {
    return os<<"IPv4 flow: "<<to_string(address);
}

auto from_capture(const struct ip* ip_header) -> std::optional<IPv4_flow> {
    return IPv4_flow{ip_header->ip_src.s_addr, ip_header->ip_dst.s_addr}; 
}

#ifdef SUPPORT_IPV6
auto from_capture(const struct ip6_hdr* ip) -> std::optional<IPv6_flow> {
	if (ip->version == 6) {
        // OK we've made it sure that we have a valid IP version here
        // now we can start working on parsing the packet
        return IPv6_flow{make_ipv6_from_network(&ip->ipSrc[0]), make_ipv6_from_network(&ip->ipDst[0])};
	} else {
		return {};
	}
    
}
#endif  // SUPPORT_IPV6

auto operator << (std::ostream& os, const TCP& t) -> std::ostream& {
    return os<<"[source port: " << t.source_port << " destination port: " << t.dest_port << ", ack number " << t.ack_num
        << ", sequence number " << t.sequence_num << ", fin: " << std::boolalpha << t.state.fin << ", ack: " << std::boolalpha << t.state.ack
        << ", syn: " << std::boolalpha << t.state.syn << ", reset: " << t.state.reset;
}

auto to_string(TCP::current_state s) -> std::string {
    std::ostringstream pa;
    pa << s;
    return pa.str();
}

auto TCP::connection_state() const -> current_state {
    if (state.syn) {
        if (state.ack) {
            return current_state::ACK_START_CONNECT;
        } else if (!(state.fin && state.reset)) {
            return current_state::START_CONNECTION;
        } else {
            return current_state::INVALID_STATE;
        }
    } else if (state.fin) {
        if (state.ack) {
            return current_state::ACK_CLOSE;
        } else {
            return current_state::START_CLOSE;
        }
    } else if (state.reset) {
        return current_state::RESET_CONNECTION;
    } else {
         if (state.ack) {
            return current_state::ACK_STATE;
        } else {
            return current_state::OTHER;
        }
    }
}

auto from_capture(const struct tcphdr* header) -> std::optional<TCP> {
    return TCP{ntohs(header->source), 
               ntohs(header->dest), 
               ntohl(header->seq), 
               ntohl(header->ack_seq), 
               header->fin == 1, 
               header->ack == 1, 
               header->syn == 1, 
               header->rst == 1
     };
}

auto operator << (std::ostream& os, const data_flow& p) -> std::ostream& {
    static_assert(sizeof(tls_header) == 5, "expecting size 5");
    char tmp_buf[64];
    time_t now_time = p.timestamp / SEC2MICRO;
    auto micros = p.timestamp % SEC2MICRO;
    auto now_tm = localtime(&now_time);
    strftime(tmp_buf, sizeof tmp_buf, "%Y-%m-%d %H:%M:%S", now_tm);
    os << "[" << tmp_buf << "." << std::setw(6) << std::setfill('0') << micros <<   "]: IPv4 layer: " 
        << p.ipv4_layer << ", TCP layer: " << p.tcp_layer << " payload size " << p.payload_size();
    if (p.has_payload()) {
        tls_header hdr{p.app_data.data()};
        if (valid(hdr)) {
            os << ", encrypted message: " << hdr;
            if (is_handshake(hdr)) {
                tls_handshake hs{p.app_data.data() + sizeof(hdr)};
                os << ", handshake: " << hs;
            } else  if (is_alert(hdr)) {
                tls_alert a{p.app_data.data() + sizeof(hdr)};
                os << ", alert: " << a;
            } else if (is_cipher_change(hdr)) {
                tls_change_cipher cc{p.app_data.data() + sizeof(hdr)};
                os <<", cipher change: " << cc;
            } else {
                os << ", either application or heartbeat";
            }
        }
    }
    return os;
}

auto to_string(const data_flow& df) -> std::string {
    std::ostringstream pa;
    pa << df;
    return pa.str();
}

auto data_flow::is_encrypted() const -> bool {
    auto msg = try_from(app_data);
    if (msg.is_ok()) {
        return valid(msg.unwrap());
    }
#ifdef DEBUG_TLS_MESSAGES    
    LOG_HTTP_PACKETS_DEBUG << "this is not a TLS packet " << *this << ": " << msg.error_value();
#endif  //   DEBUG_TLS_MESSAGES  
    return false;
}

auto from_capture(const struct pcap_pkthdr* header, const std::uint8_t* packet, std::size_t ether_len) -> std::optional<data_flow> {

    //const auto *eth_header = (const struct ether_header *) packet;
    auto t = type_from_capture({packet,  header->caplen}, ether_len); //ntohs(eth_header->ether_type); 
    if (t == ethernet_type::ETHER_IPv4) {
        const auto ip_header_ptr = (const ip*)(packet + ether_len);//(struct ip*)ip_header;
        // The second-half of the first byte in ip_header
        //   contains the IP header length (IHL). 
        auto ip_header_length = ip_header_ptr->ip_hl * OCTETS_2_BYTES;//((*ip_header) & 0x0F);
        decltype(header->caplen) packet_len = ntohs(ip_header_ptr->ip_len) + std::uint32_t(ether_len);
        if (packet_len != header->caplen) {
            packet_len = std::min(packet_len, header->caplen);
        }
        // The IHL is number of 32-bit segments. Multiply
        //   by four to get a byte count for pointer arithmetic 
        auto protocol = ip_header_ptr->ip_p;
        if (protocol == IPPROTO_TCP) {
            auto ipv4_flow = from_capture(ip_header_ptr);    // make sure this succeed
            // try going to TCP layer
            auto tcp_header = packet + ether_len + ip_header_length;
            auto [tcp_layer, payload] = parse_tcp_packet(tcp_header, packet, packet_len, ip_header_length, ether_len);
            if (ipv4_flow && tcp_layer) {
                data_flow::timestamp_t ts = header->ts.tv_sec * SEC2MICRO + header->ts.tv_usec;

                return data_flow{ts, std::move(*ipv4_flow), std::move(*tcp_layer), std::move(payload)};
            }
        }
    }
    return {};
        
}

auto operator << (std::ostream& os, TCP::current_state s) -> std::ostream& {
    switch (s) {
        case TCP::current_state::ACK_CLOSE:
            return os << "ACK close";
        case TCP::current_state::ACK_START_CONNECT:
            return os << "ACK start connect";
        case TCP::current_state::ACK_STATE:
            return os << "ACK";
        case TCP::current_state::INVALID_STATE:
            return os << "invalid";
        case TCP::current_state::RESET_CONNECTION:
            return os << "reset";
        case TCP::current_state::START_CLOSE:
            return os << "start close";
        case TCP::current_state::START_CONNECTION:
            return os << "start connection";
        default:
            return os << "unknown";

    }
}

auto to_string(ethernet_type et) -> std::string_view {
    switch (et) {
        case ethernet_type::ETHER_ERROR_TYPE:
            return "invalid ethernet type";
        case ethernet_type::ETHER_IPv4:
            return "IPv4";
        case ethernet_type::ETHER_IPv6:
            return "IPv6";
        case ethernet_type::ETHER_VLAN:
            return "VLAN";
        default:
            return "unknown ethernet type";

    }
}

}           // end of namespace monitor
