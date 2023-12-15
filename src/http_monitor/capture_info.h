#pragma once
#include "results.h"
#include <string>
#include <array>
#include <vector>
#include <cstddef>
#include <optional>
#include <iosfwd>
#include <algorithm>

struct tcphdr;
struct ip;
struct ip6_hdr;
struct pcap_pkthdr;

namespace monitor
{
constexpr std::string_view ANY_DEVICE = "any";

enum ethernet_type {
    ETHER_UNKOWN = 0,
    ETHER_IPv4,
    ETHER_IPv6,
    ETHER_VLAN,
    ETHER_ERROR_TYPE
};

auto to_string(ethernet_type et) -> std::string_view;

auto type_from_capture(const std::basic_string_view<std::uint8_t> cap, std::size_t offset) -> ethernet_type;

enum class FlowMatch {
    NO_MATCH,
    SAME_DIRECTION,
    OPPOSITE_DIRECTION
};

inline constexpr auto ethernet_header_len() -> std::size_t {
    return 14;  // this is always true for all incoming packets
}

inline constexpr auto ethernet_header_len_any( )-> std::size_t {
    return ethernet_header_len() + 2;
}

inline constexpr auto ethernet_header_expected_len(bool dev_any) -> std::size_t {
    if (dev_any) {
        return ethernet_header_len_any();
    }
    return ethernet_header_len();
}

inline constexpr auto ethernet_header_expected_len(const std::string_view dev) -> std::size_t {
    return ethernet_header_expected_len(dev == ANY_DEVICE);
}


// Holds the minumum information we need on IPv4 layer
struct IPv4
{
    using address_type = std::uint32_t;

    constexpr IPv4() = default;
    constexpr explicit IPv4(address_type addr) : address{addr} {
    }

    address_type address = 0;
};

auto to_string(IPv4 ip) -> std::string;
auto operator << (std::ostream&, IPv4 address) -> std::ostream&;
inline constexpr auto operator == (IPv4 left, IPv4 right) -> bool {
    return left.address == right.address;
}

inline constexpr auto operator != (IPv4 left, IPv4 right) -> bool {
    return !(left == right);
}

// Holds the minumum information we need on IPv6 layer
struct IPv6
{
    static constexpr std::size_t address_len = 16;
    using address_type = std::array<std::uint8_t, address_len>;

    IPv6() = default;
    IPv6(address_type addr) : address(std::move(addr)) {
    }

    explicit IPv6(const std::uint8_t* raw_mem) {
        std::copy(raw_mem, raw_mem + address_len, address.data());
    }
    
    address_type address;
};
    
auto to_string(IPv6 ip) -> std::string;
auto operator << (std::ostream&, IPv6 address) -> std::ostream&;
inline auto operator == (IPv6 left, IPv6 right) -> bool {
    return std::equal(left.address.begin(), left.address.end(), right.address.data());
}
        
inline auto operator != (IPv6 left, IPv6 right) -> bool {
    return !(left == right);
}   

// Each IP layer contains both the source as well as the destination IP
// This where we keeping them
struct IPv4_flow 
{       
    constexpr IPv4_flow() = default;
    constexpr IPv4_flow(IPv4::address_type src, IPv4::address_type dst) :
        source{src}, dest{dst} {
    }

    constexpr IPv4_flow(IPv4 src, IPv4 dst) :
        source{src}, dest{dst} {
    }
    
    IPv4 source;
    IPv4 dest; 
};

auto to_string(IPv4_flow flow) -> std::string;
auto operator << (std::ostream&, IPv4_flow address) -> std::ostream&;
inline constexpr auto operator == (IPv4_flow left, IPv4_flow right) -> bool {
    return left.source == right.source && left.dest == right.dest;
}

auto from_capture(const struct ip*) -> std::optional<IPv4_flow>;

inline constexpr auto same_session(IPv4_flow curr, IPv4_flow new_msg) -> FlowMatch {
    // if port match in either direction, then they belong to the same session
    if (curr == new_msg) {
        return FlowMatch::SAME_DIRECTION;
    }
    if (IPv4_flow{new_msg.dest, new_msg.source} == curr) {
        return FlowMatch::OPPOSITE_DIRECTION;
    }
    return FlowMatch::NO_MATCH;
}

struct IPv6_flow 
{       
    IPv6_flow() = default;
    IPv6_flow(IPv6::address_type src, IPv6::address_type dst) :
        source{src}, dest{dst} {
    }

    IPv6_flow(IPv6 src, IPv6 dst) :
        source{src}, dest{dst} {
    }
    
    IPv6 source;
    IPv6 dest; 
};

auto to_string(IPv6_flow flow) -> std::string;
auto operator << (std::ostream&, IPv6_flow address) -> std::ostream&;
inline auto operator == (IPv6_flow left, IPv6_flow right) -> bool {
    return left.source == right.source && left.dest == right.dest;
}   

#ifdef SUPPORT_IPV6
auto from_capture(const struct ip6_hdr*) -> std::optional<IPv6_flow>;
#endif  // SUPPORT_IPV6
inline auto same_session(IPv6_flow curr, IPv6_flow new_msg) -> FlowMatch {
    // if port match in either direction, then they belong to the same session
    if (curr == new_msg) {
        return FlowMatch::SAME_DIRECTION;
    }
    if (IPv6_flow{new_msg.dest, new_msg.source} == curr) {
        return FlowMatch::OPPOSITE_DIRECTION;
    }
    return FlowMatch::NO_MATCH;
}

// Layer 4 transport minimum information to keep
struct TCP
{
    using port_type = std::uint16_t;
    using counter_type = std::uint32_t;
    struct state_t
    {
        bool fin: 1;
        bool ack: 1;
        bool syn: 1;
        bool reset: 1;
        char unused: 4;

        state_t() : 
            fin{false}, ack{false}, syn{false}, reset{false}, unused{0} {
        } 

        state_t(bool f, bool a, bool s, bool r) : 
            fin{f}, ack{a}, syn{s}, reset{r}, unused{0} {
        } 
    };

    enum class current_state : std::uint8_t {
        START_CONNECTION,       // only the syn is on
        ACK_START_CONNECT,      // both syn and ack are on
        START_CLOSE,            // FIN is on
        ACK_CLOSE,              // FIN and ACK are one
        RESET_CONNECTION,       // the connection is invalid - closing
        ACK_STATE,              // we have some ack sent
        OTHER,                  // not sure what this is
        INVALID_STATE           // something don't make sense here
    };

    port_type source_port = 0;
    port_type dest_port = 0;
    counter_type ack_num = 0;
    counter_type sequence_num = 0;
    state_t state;

    TCP() = default;
    TCP(port_type sp, port_type dp, counter_type ac, counter_type sn, bool f, bool a, bool s, bool r) :
        source_port{sp}, dest_port{dp}, ack_num{ac}, sequence_num{sn}, state{f, a, s, r} {
    }

    constexpr auto fin_sent() const -> bool {
        return state.fin;
    }

    constexpr auto acked() const -> bool {
        return state.ack;
    }

    constexpr auto syn_packet() const -> bool {
        return state.syn;
    }

    constexpr auto is_reseting() const -> bool {
        return state.reset;
    }

    auto connection_state() const -> current_state;

    auto control_only() const -> bool {
        return  connection_state() == current_state::ACK_STATE;
    }
};

inline constexpr auto same_flow(const TCP& left, const TCP& right) -> bool {
    return left.source_port == right.source_port && left.dest_port == right.dest_port;
}

inline constexpr auto should_drop(const TCP& last_seen, const TCP& new_msg) -> bool {
    if (same_flow(last_seen, new_msg)) {
        return last_seen.sequence_num > new_msg.sequence_num;
    }
    return false;
}

inline constexpr auto same_session(const TCP& last_seen, const TCP& new_msg) -> FlowMatch {
   if (should_drop(last_seen, new_msg)) {
        return FlowMatch::NO_MATCH;
   }
   if (!same_flow(last_seen, new_msg)) {
        // maybe this is coming from the other direction
        return new_msg.source_port == last_seen.dest_port && 
            new_msg.dest_port == last_seen.source_port ? FlowMatch::OPPOSITE_DIRECTION :
                                                         FlowMatch::NO_MATCH;
   }
   return FlowMatch::SAME_DIRECTION; // same flow == true
}

// Note the headers len value is used to calculate the payload len out of the packet that we are processing
auto from_capture(const struct tcphdr* header) -> std::optional<TCP>;
auto operator << (std::ostream& os, const TCP& t) -> std::ostream&;
auto operator << (std::ostream& os, TCP::current_state s) -> std::ostream&;
auto to_string(TCP::current_state s) -> std::string;

// This data type encapsulate all layers that we are getting from the network
// We are only saving here the 2 layers - IP layer, TCP layer and for 
// anything that was sent over TCP we will just keep it as opaque data, meaning
// just collection of bytes
struct data_flow
{
    using application_data = std::basic_string<std::uint8_t>;
    using timestamp_t = std::uint64_t;

    timestamp_t timestamp = 0;
    IPv4_flow ipv4_layer;
    TCP       tcp_layer;
    application_data app_data;

    data_flow() = default;

    data_flow(timestamp_t ts, IPv4_flow ipv4f, TCP t, application_data pl = {}) :
        timestamp{ts}, 
        ipv4_layer{std::move(ipv4f)}, 
        tcp_layer{std::move(t)}, 
        app_data{std::move(pl)} {
        
    }

    data_flow(timestamp_t ts, IPv4_flow ipv4f, TCP t, const std::uint8_t* from, const std::uint8_t* to) :
        data_flow{ts, ipv4f, t, application_data(from, to)} {
    }

    [[nodiscard]] auto has_payload() const -> bool {
        return !app_data.empty();
    }

    [[nodiscard]] auto payload_size() const -> std::size_t {
        return app_data.size();
    }
    [[nodiscard]] constexpr auto fin_sent() const -> bool {
        return tcp_layer.fin_sent();
    }

    [[nodiscard]] constexpr auto acked() const -> bool {
        return tcp_layer.acked();
    }

    [[nodiscard]] constexpr auto syn_packet() const -> bool {
        return tcp_layer.syn_packet();
    }

    [[nodiscard]] constexpr auto is_reseting() const -> bool {
        return tcp_layer.is_reseting();
    }

    [[nodiscard]] auto control_only() const -> bool {
        return !has_payload() && tcp_layer.control_only();
    }

    // note that by itself we are not sure if this is true
    // but for the caller is can mean that it does,
    // but in order to make sure that this is the case,
    // the caller must make sure that we have seen this both ways
    [[nodiscard]] auto is_encrypted() const -> bool;
    
    auto payload_2_string() -> std::string {
        if (!app_data.empty()) {
            return std::string{reinterpret_cast<char*>(app_data.data()), app_data.size()};
        }
        return {};
    }

    auto str() const -> std::string_view {
        if (!app_data.empty()) {
            return std::string_view{reinterpret_cast<const char*>(app_data.data()), app_data.size()};
        }
        return {};
    }
};

// This is the interface from which it would be called for processing the packet from the packet capture lib (libpcap).
// Note that we are assuming that the calling function checked that this is a valid IPv4 packet (we will assert this)
// as well as that we have a valid packet size (we will assert this is well).
// In case this packet is not IPv4 we will not return a result - std::nullopt, since we cannot check this in advance
// Note that for support IPv6 as well as supporting none TCP protocols, we will need other types.
[[nodiscard]] auto from_capture(const struct pcap_pkthdr* header, const std::uint8_t* packet, std::size_t ether_len) -> std::optional<data_flow>;

[[nodiscard]] inline constexpr auto same_session(const data_flow& last_seen, const data_flow& new_msg) -> FlowMatch {
    // check whether the packet is matching the layers in either direction
    auto ret = same_session(last_seen.ipv4_layer, new_msg.ipv4_layer); 
    if (ret != FlowMatch::NO_MATCH) {
        ret = same_session(last_seen.tcp_layer, new_msg.tcp_layer);
    }
    return ret;
        
}

auto operator << (std::ostream& os, const data_flow& p) -> std::ostream&;
auto to_string(const data_flow& df) -> std::string;



}   // end of namespace monitor
