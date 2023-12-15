#pragma once
#include "capture_info.h"
#include "results.h"
#include "unordered_dense.h"
#include <optional>
#include <iosfwd>
#include <string>
#include <string_view>
#include <vector>

namespace monitor
{

inline constexpr auto make_id(const data_flow& from) -> std::uint64_t {
    constexpr std::uint64_t FACTOR = 97;
    constexpr std::uint64_t PROTOCOL_FACTOR = FACTOR * 4;
    return from.ipv4_layer.dest.address * FACTOR ^ 
            from.ipv4_layer.source.address * FACTOR ^ 
            from.tcp_layer.source_port * FACTOR ^ 
            from.tcp_layer.dest_port * FACTOR ^ 
            PROTOCOL_FACTOR;
}   
struct flows_stream
{
    using flows_collection_t = std::vector<data_flow>;
    using value_type = flows_collection_t::value_type;
    using iterator = flows_collection_t::iterator;
    using const_iterator = flows_collection_t::const_iterator;
    using reference = flows_collection_t::reference;
    using const_reference = flows_collection_t::const_reference;

    flows_stream()  = default;
    explicit flows_stream(flows_collection_t from) : data{std::move(from)} {
    }

    [[nodiscard]] auto size() const -> std::size_t {
        return data.size();
    }

    [[nodiscard]] auto empty() const -> bool {
        return data.empty();
    }

    auto begin() -> iterator {
        return data.begin();
    }

    auto end() -> iterator {
        return data.end();
    }

    auto begin() const -> const_iterator {
        return data.begin();
    }

    auto end() const -> const_iterator {
        return data.end();
    }

    auto back() -> reference {
        return data.back();
    }

    auto back() const -> const_reference {
        return data.back();
    }

    auto front() -> reference {
        return data.front();
    }

    auto front() const -> const_reference {
        return data.front();
    }

    auto clear() -> void {
        data.clear();
    }

    auto reorder() -> void; // try to make sure that we have the right order for packets

    [[nodiscard]] auto data_size() const -> std::size_t;

    [[nodiscard]] auto as_string() -> std::string;

    flows_collection_t data;
};

auto operator << (std::ostream& os, const flows_stream& dp) -> std::ostream&;

struct session_payload
{
    // holds a list of all the payloads - both up and down
    using flows_collection_t = flows_stream;

    session_payload() = default;
    explicit session_payload(bool p) : partial{p} {
    }

    session_payload(flows_stream up, flows_stream down, bool part) :
        upstream{std::move(up)}, downstream{std::move(down)}, partial{part} {

    }

    [[nodiscard]] auto size() const -> std::size_t {
        return upstream.size() + downstream.size();
    }

    [[nodiscard]] auto empty() const -> bool {
        return upstream.empty() && downstream.empty();
    }

    [[nodiscard]] auto downstream_size() const -> std::size_t {
        return downstream.data_size();
    }

    [[nodiscard]] auto upstream_size() const -> std::size_t {
        return upstream.data_size();
    }

    [[nodiscard]] auto payloads_memory() const -> std::size_t {
        return downstream_size() + upstream_size();
    }

    [[nodiscard]] auto not_ready_size() const -> bool {
        return upstream_size() == 0 || downstream_size()  == 0;
    }

    [[nodiscard]] auto is_encrypted() const -> bool {
        if (!upstream.empty() && !downstream.empty()) {
            return upstream.back().is_encrypted() || downstream.back().is_encrypted();
        }
        return false;
    }

    [[nodiscard]] constexpr auto is_partial() const -> bool {
        return partial;
    }

    flows_collection_t upstream;
    flows_collection_t downstream;
    bool partial = false;
};

auto operator << (std::ostream& os, const session_payload& dp) -> std::ostream&;
auto info(const session_payload& sp) -> std::string;
auto detailed_info(const session_payload& sp) -> std::string;

// From a list of packets we can form a session - packets that were flow from both direction
// on the connection from the client to the server and back
struct session
{
    enum insert_error 
    {
        NOT_SYN_PACKET,
        SYN_ON_SYN_PACKET,
        NOT_ACK_ON_START,
        TRY_INSERT_ON_NONE_MATCH,
        ENCRYPTED_PACKET,
        INVALID_CALL_TO_INSERT_ON_EMPTY
    };
    struct flows
    {
        // this divides the flows into to types
        // control flows, who don't have data
        // and data flow that we can use for message parsing
        using flows_collection_t = flows_stream;

        [[nodiscard]] constexpr auto control() const -> const flows_collection_t& {
            return control_flows;
        }

        [[nodiscard]] constexpr auto data() const -> const flows_collection_t& {
            return data_flows;
        }

        [[nodiscard]] constexpr auto data() -> flows_collection_t& {
            return data_flows;
        }

        [[nodiscard]] constexpr auto ready() const -> bool {
            return pending_keepalive.has_value();
        }

        [[nodiscard]] auto belong(const data_flow& new_packet) const -> bool;

        [[nodiscard]] auto connection_id() const -> const data_flow& {
            return control_flows.data.front();
        }

        [[nodiscard]] auto size() const -> std::size_t {
            return control_flows.size() + data_flows.size();
        }

        [[nodiscard]] auto no_control() const -> bool {
            return control_flows.empty();
        }

        [[nodiscard]] auto empty() const -> bool {
            return control_flows.empty() && data_flows.empty();
        }

        [[nodiscard]] auto data_size() const -> std::size_t;

        [[nodiscard]] auto try_insert(data_flow new_packet, bool upstream) -> result<bool, insert_error>;

        [[nodiscard]] auto done() const -> bool;

        [[nodiscard]] auto try_insert_new(data_flow new_packet) -> result<bool, insert_error>;

        [[nodiscard]] auto lifetime() const -> data_flow::timestamp_t {
            if (no_control()) {
                return 0;
            }
            if (data_flows.empty()) {
                return control_flows.data.back().timestamp;
            }
            return data_flows.data.back().timestamp;
        }

        [[nodiscard]] auto reset_connection() const -> bool {
            return no_control() ? false : control().back().is_reseting();
        }

        auto update_keep_alive() -> void {
            if (pending_keepalive.has_value()) {
                if (!data_flows.empty()) {
                    data_flows.clear();
                }
                data_flows.data.push_back(std::move(*pending_keepalive));
                pending_keepalive = std::nullopt;
            }
        }

        auto clear() -> void {
            data_flows.clear();
        }

        [[nodiscard]] auto is_encrypted() const -> bool;

        [[nodiscard]] auto take() -> flows_collection_t; // after the call to this function all data_flows placed at return value
    private:
        auto insert_upstream_payload(data_flow nwe_flow) -> result<bool, insert_error>;

    private:
        flows_collection_t control_flows;
        flows_collection_t data_flows;
        std::optional<flows_stream::flows_collection_t::value_type> pending_keepalive;
    };

    session() = default;

    [[nodiscard]] auto ready() const -> bool {
        return upstream.ready();
    }

    auto take() -> session_payload;

    // checks whether we this packet belong to the current session,
    // meaning that we have a match for the first packet here in term
    // of TCP and IP layers
    [[nodiscard]] auto belong(const data_flow& new_packet) -> bool;

    // note that this would consume the packet so call belong above before!
    // please note that if we have an issue with new flow. such as we saw
    // that this is HTTPS and not HTTP (so we cannot parse it), it would not be
    // able to insert.
    [[nodiscard]] auto try_insert(data_flow new_packet) -> result<bool, insert_error>;

    [[nodiscard]] auto try_insert_new(data_flow new_packet) -> result<bool, insert_error>;

    [[nodiscard]] auto packets_count() const -> std::size_t {
        return upstream.size() + downstream.size();
    }

    [[nodiscard]] auto empty() const -> bool {
        return upstream.empty() && downstream.empty();
    }
    
    // return true if we have a notification from TCP layer
    // that the session is closed
    [[nodiscard]] auto done() const -> bool;

    // how long do we have this session opened -> i.e. when
    // did we have the first packet
    [[nodiscard]] auto lifetime() const -> data_flow::timestamp_t;

    // return the amount of memory that is used by this session
    // note that we are only counting payload size for both ends
    [[nodiscard]] auto payloads_memory() const -> std::size_t;

    // report about the session - basically return string with data about first from from each direction
    auto info() const -> std::string;

    [[nodiscard]] auto is_encrypted() const -> bool;

    auto marked_partial() -> void {
        partial = true;
    }

    [[nodiscard]] constexpr auto is_partial() const -> bool {
        return partial;
    }

    [[nodiscard]] auto not_ready_size() const -> bool;
    [[nodiscard]] auto upstream_size() const -> std::size_t;
    [[nodiscard]] auto downstream_size() const -> std::size_t;

    [[nodiscard]] auto downstream_flows() const -> std::size_t {
        return downstream.size();
    }
    [[nodiscard]] auto upstream_flows() const -> std::size_t {
        return upstream.size();
    }

    [[nodiscard]] auto connection_id() const -> const flows::flows_collection_t::value_type& {
        return upstream.connection_id();
    }

    [[nodiscard]] auto downstream_id() const -> const flows::flows_collection_t::value_type& {
        return downstream.connection_id();
    }

    [[nodiscard]] auto first_upstream() -> flows::flows_collection_t::value_type& {
        return upstream.data().front();
    }

    [[nodiscard]] auto first_downstream() const -> const flows::flows_collection_t::value_type& {
        return downstream.data().front();
    }

    auto print(std::ostream& os) const -> std::ostream&;

    // this is mostly for testing, but in any case, we can
    // double check that we have all the right flows
    [[nodiscard]] auto verify_flows() const -> result<bool, std::string>;

private:
    auto verify_keep_alive() -> void {
        upstream.update_keep_alive();
    }

private:
    flows upstream;         // holds the packets from client (ones that come first and all that matched)
    flows downstream;       // holds the packets from the server (ones that come with the opposite to the upstream packets)
    bool partial = false;       // this means that we cannot see all packets because the message it too big
};

auto take_if(session& s) -> std::optional<session_payload>;

auto operator << (std::ostream& os, const session& s) -> std::ostream&;
auto operator << (std::ostream& os, session::insert_error ie) -> std::ostream&;
auto operator << (std::ostream& os, const session::flows& f) -> std::ostream&;

struct sessions_repo
{
    using sessions_t = ankerl::unordered_dense::segmented_map<std::uint64_t, session>;

    sessions_repo() = default;

    // this may fail, so return false, if we don't have a location
    // to save it to
    [[nodiscard]] auto add_flow(data_flow new_flow) -> sessions_t::iterator;

    [[nodiscard]] auto empty() const -> bool {
        return sessions.empty();
    }

    [[nodiscard]] auto saved() const -> std::size_t {
        return sessions.size();
    }

    [[nodiscard]] auto begin() -> sessions_t::iterator {
        return sessions.begin();
    }

    [[nodiscard]] auto end() -> sessions_t::iterator {
        return sessions.end();
    }

    [[nodiscard]] auto begin() const -> sessions_t::const_iterator {
        return sessions.begin();
    }

    [[nodiscard]] auto end() const -> sessions_t::const_iterator {
        return sessions.end();
    }

    auto set_rate_limit(std::uint64_t max_msg) -> void {
        rate_limit_session = max_msg;
    }

    sessions_t sessions;

private:
    static constexpr std::uint64_t NOT_MAX_MESSAGE = 0xffffffff;
    std::uint64_t rate_limit_session = NOT_MAX_MESSAGE;
};

}   // end of namespace monitor