#include "session.h"
#include "Log/logging.h"
#include "http_match.h"
#include <algorithm>
#include <numeric>
#include <iostream>
#include <sstream>

namespace monitor
{

using namespace std::string_literals;

namespace
{

auto make_fake_connect_flow(const data_flow& from) -> data_flow {
    auto tcp = from.tcp_layer;
    auto ip = from.ipv4_layer;
    std::swap(tcp.dest_port, tcp.source_port);
    std::swap(ip.dest, ip.source);
    tcp.state.ack = false;
    data_flow new_flow{from};
    new_flow.tcp_layer = tcp;
    new_flow.ipv4_layer = ip;
    return new_flow;
}

auto calculate_payloads(const flows_stream::flows_collection_t& flows) -> std::size_t {
    return std::accumulate(std::begin(flows), std::end(flows), 0lu, [] (std::size_t cur, const auto& f) {
        return cur + f.payload_size();
    });
}

auto make_new_session(data_flow new_flow) -> std::optional<session> {
    
    if (new_flow.syn_packet()) {
        session new_session;
        if (const auto e = Error(new_session.try_insert_new(std::move(new_flow))); e) {
            return {};
        }
        
        return new_session;
    } else {
        if (new_flow.has_payload() && parser::is_http_request_start(new_flow.str())) {
            // we need to create a "fake" new connection flow, and then create this in the new session
            data_flow connect_flow{new_flow.timestamp, new_flow.ipv4_layer, new_flow.tcp_layer};
            connect_flow.tcp_layer.state.syn = true;
            connect_flow.tcp_layer.state.ack = false;
            if (auto new_session = make_new_session(std::move(connect_flow)); new_session) {
                const auto b = new_session->try_insert(std::move(new_flow));
                if (b) {
                    return new_session;
                }
            }
        }
    }
    return {};
}

auto session_details(std::string_view tag, const session_payload::flows_collection_t& sp) -> std::string {
    constexpr std::size_t max_str_display = 64;

    std::ostringstream formatter;
    formatter << tag << ": ";
    if (sp.empty()) {
        formatter << "empty";
    } else {
        auto it = std::min(2lu, sp.size()); // at most only the first two packets
        for (auto i = 0lu; i < it; i++) {
            auto df = sp.data[i];
            formatter << sp.data[i];
            if (sp.data[i].has_payload()) {
                auto ds = std::min(max_str_display, sp.data[i].app_data.size());    // don't show all the packet's payload
                formatter << ", payload {" << sp.data[i].str().substr(0, ds) << "}";
            } else {
                formatter << ", no payload";
            }
        }
    }
    return formatter.str();
}

}       // end of local namespace

auto operator << (std::ostream& os, session::insert_error ie) -> std::ostream& {
    switch (ie) {
        case session::NOT_ACK_ON_START:
            return os << "we have empty downstream list for, but this is not ACK start connection";
        case session::NOT_SYN_PACKET:
            return os << "cannot insert new session, this is not a correct first session type";
        case session::SYN_ON_SYN_PACKET:
            return os << "got syn packet for the same direction - syn packet can only come for different direction";
        case session::TRY_INSERT_ON_NONE_MATCH:
            return os << "trying to insert packet that don't belong to a session";
        case session::ENCRYPTED_PACKET:
            return os << "ignoring encrypted packet as it cannot be parsed";
        case session::INVALID_CALL_TO_INSERT_ON_EMPTY:
            return os << "you cannot start a new session when it is not empty!";
        default:
            return os << "unknown error for insert new flow";
    }
}

auto operator << (std::ostream& os, const flows_stream& dp) -> std::ostream& {
    std::copy(std::begin(dp), std::end(dp), std::ostream_iterator<flows_stream::flows_collection_t::value_type>(os, "\n\t\t"));
    return os;
}

auto operator << (std::ostream& os, const session_payload& dp) -> std::ostream& {
    os << "upstream:\n" << dp.upstream << "\ndownstream: " << dp.downstream;
    return os;
}

auto info(const session_payload& dp) -> std::string {
    std::ostringstream display;
    if (dp.empty()) {
        display << "empty";
    } else {
        if (!dp.upstream.empty()) {
            display << "upstream from: " << dp.upstream.front();
        }
        if (!dp.downstream.empty()) {
            display << ", downstream from: " << dp.downstream.front();
        }
    }
    return display.str();
}

auto detailed_info(const session_payload& sp) -> std::string {
    return session_details("upstream", sp.upstream) + "\n" + session_details("downstream", sp.downstream);
}

auto count_fin_packets = [count = 1lu] (auto yes) mutable {
    if (yes) {
        count++;
    }
    if ((count % 1'000) == 0) {
        LOG_HTTP_PACKETS_INFO << "seen " << count << " done packet so far";
    }
};

auto session::flows::done() const -> bool {
    if (no_control()) {
        return false;
    }

    return control().back().fin_sent();
    
}



auto session::flows::data_size() const -> std::size_t {
    return calculate_payloads(data_flows.data);
}

auto session::flows::belong(const data_flow& new_flow) const -> bool {
    if (!no_control()) {
        return same_session(control().front(), new_flow) != FlowMatch::NO_MATCH;
    }
    return false;
}

auto session::flows::insert_upstream_payload(data_flow new_flow) -> result<bool, insert_error> {
    if (parser::is_http_request_start(new_flow.str()) && !data_flows.empty()) {
        pending_keepalive = std::move(new_flow);    // in the middle of keep alive we have new HTTP request
        return ok(true);
    }
    data_flows.data.push_back(std::move(new_flow));
    return ok(true);
}

auto session::flows::try_insert(data_flow new_packet, bool upstream) -> result<bool, insert_error> {
    constexpr auto skip_encrypt = [] (const auto& df, const auto& new_flow) -> bool {
        return !df.empty() &&  df.back().is_encrypted() && new_flow.has_payload();
    };

    if (new_packet.fin_sent() || new_packet.is_reseting()) {
        count_fin_packets(true);
    }

    if (no_control()) {
        return try_insert_new(std::move(new_packet));
    }
    // we need to see what type of packet we have here..
    if (skip_encrypt(data_flows, new_packet)) {
        return failed(ENCRYPTED_PACKET);    // we are ignoring in this case.. 
    }
    if (new_packet.syn_packet()) {              // this cannot be - another syn that is not the first
        return failed(SYN_ON_SYN_PACKET);
    }
    if (new_packet.has_payload()) {     // this is not a control message
        if (upstream) {                 // we need to make sure that this is not the start of new session even if not closed (keep alive)
           return insert_upstream_payload(std::move(new_packet));
        } else {    // for downstream we don't care much
            data_flows.data.push_back(std::move(new_packet));
            return ok(true);
        }
    } else {
        if (new_packet.control_only()) {
            return failed(INVALID_CALL_TO_INSERT_ON_EMPTY);
        }
        control_flows.data.push_back(std::move(new_packet));
        return ok(true);
    }
    
}

auto session::flows::try_insert_new(data_flow new_flow) -> result<bool, insert_error> {
    // First make sure that this can really be the first packet in the session.
    // For TCP this must be in state == START_CONNECTION, otherwise this is
    // some tray packet that we just need to ignore
    if (no_control()) {
        switch (new_flow.tcp_layer.connection_state()) {
            case TCP::current_state::START_CONNECTION:
            case TCP::current_state::ACK_START_CONNECT:
                // both of these cases are legal for the first entry
                control_flows.data.push_back(std::move(new_flow));
                return ok(true);
            default:
                return failed(NOT_SYN_PACKET);
        }
    }
    return failed(NOT_SYN_PACKET);
}

auto session::flows::is_encrypted() const -> bool {
    // search from the end, since it should be closer to it
    return data_flows.empty() ? false : data_flows.back().is_encrypted();
}

auto session::flows::take() -> flows_collection_t {
    flows_collection_t ret;
    std::swap(ret, data_flows);
    return ret;
}

auto session::belong(const data_flow& new_packet) -> bool {
    if (empty() || done() || upstream.empty()) {
        return false;
    }
    return upstream.belong(new_packet);
}

auto session::try_insert_new(data_flow new_packet) -> result<bool, insert_error> {
    if (!empty()) {
        return failed(INVALID_CALL_TO_INSERT_ON_EMPTY);
    }
    if (new_packet.acked()) {
        // we cannot afford to insert without upstream to the downstream
        auto cf = make_fake_connect_flow(new_packet);
        const auto r = upstream.try_insert_new(std::move(cf));
        if (r.is_ok()) {
            return downstream.try_insert_new(std::move(new_packet));    // this is not "normal", but maybe we lost the upstream packet
        }
        return r;
    }
    return upstream.try_insert_new(std::move(new_packet));
}

auto session::is_encrypted() const -> bool {
    if (upstream.empty() || downstream.empty()) {
        return false;
    }
    
    return upstream.is_encrypted() || downstream.is_encrypted();
}

auto session::try_insert(data_flow new_packet) -> result<bool, insert_error> {
    if (empty()) {
        return try_insert_new(std::move(new_packet));
    }
    // at this point we know that this is not the first packet
    // make sure that this packet belong here, and make if so
    // see to which side it belong
    if (make_id(upstream.connection_id()) == make_id(new_packet)) {
        auto r = same_session(upstream.connection_id(), new_packet);
        if (r == FlowMatch::SAME_DIRECTION) {        // new upstream packet
            return upstream.try_insert(std::move(new_packet), true);
        } else {                                        // then it must be downstream packet in this session
            // this is not so easy any more, if we are missing the connection, but we have the a persist connection
            // we need to validate..
            if (downstream.no_control()) {
                // maybe this is HTTP response message?
                if (new_packet.has_payload() && !new_packet.syn_packet() && parser::is_http_response_start(new_packet.str())) {                    
                    data_flow connect_flow{new_packet.timestamp, new_packet.ipv4_layer, new_packet.tcp_layer};
                    connect_flow.tcp_layer.state.syn = true;
                    connect_flow.tcp_layer.state.ack = true;
                    if (const auto e = Error(downstream.try_insert(std::move(connect_flow), false)); e) {                    
                        return failed(*e);
                    }
                }
            }
            return downstream.try_insert(std::move(new_packet), false);
        }
        return ok(true);
    }
    return failed(TRY_INSERT_ON_NONE_MATCH);
}

auto session::verify_flows() const -> result<bool, std::string> {
    constexpr auto match_op_flows = [] (const data_flow& left, const data_flow& right) -> bool {
        return left.ipv4_layer.dest == right.ipv4_layer.source &&
            left.ipv4_layer.source == right.ipv4_layer.dest && 
            left.tcp_layer.source_port == right.tcp_layer.dest_port &&
            left.tcp_layer.dest_port == right.tcp_layer.source_port;
    };

    constexpr auto match_flows = [] (const data_flow& left, const data_flow& right) -> bool {
        return left.ipv4_layer.source == right.ipv4_layer.source &&
            left.ipv4_layer.dest == right.ipv4_layer.dest && 
            left.tcp_layer.source_port == right.tcp_layer.source_port &&
            left.tcp_layer.dest_port == right.tcp_layer.dest_port;
    };

    if (empty()) {
        return ok(true);    // nothing to see here ..
    }

    if (!upstream.control().empty()) {
        const auto& first = upstream.connection_id();
        for (std::size_t i = 1; i < upstream.control().size(); i++) {
            if (!match_flows(first, upstream.control().data[i])) {
                return failed("upstream: at index "s + std::to_string(i) + "\nwe have unmatched flows:\n" + to_string(first) + "\nand\n" + to_string(upstream.control().data[i]) + "\nat line " + std::to_string(__LINE__));
            }
        }
        if (!upstream.data().empty()) {
            for (std::size_t i = 0; i < upstream.data().size(); i++) {
                if (!match_flows(first, upstream.data().data[i])) {
                    return failed("upstream: at index "s + std::to_string(i) + " we have unmatched flows:\n" + to_string(first) + "\nand\n" + to_string(upstream.data().data[i]) + "\nat line " + std::to_string(__LINE__));
                }
            }
        }
        if (downstream.control().empty()) {
            if (downstream.data().empty()) {
                return ok(true);
            } else {
                return failed("we don't have control flows for downstream, but we do have flows for it with data, this is not possible!"s + ", at line " + std::to_string(__LINE__));
            }
        }
        for (std::size_t i = 0; i < downstream.control().size(); i++) {
            if (!match_op_flows(first, downstream.control().data[i])) {
                return failed("downstream: at index "s + std::to_string(i) + " we have unmatched flows:\n" + to_string(first) + "\nand\n" + to_string(downstream.control().data[i]) + "\nat line " + std::to_string(__LINE__));
            }
        }
        if (!downstream.data().empty()) {
            for (std::size_t i = 0; i < downstream.data().size(); i++) {
                if (!match_op_flows(first, downstream.data().data[i])) {
                    return failed("downstream: at index "s + std::to_string(i) + " we have unmatched flows:\n" + to_string(first) + "\nand\n" + to_string(downstream.data().data[i]) + "\nat line " + std::to_string(__LINE__));
                }
            }
        }
    } else {
        return failed("no control flows for upstream - but the session is not empty"s);
    }
    return ok(true);
}

auto session::done() const -> bool {
    return (upstream.reset_connection() || downstream.reset_connection()) ||    // in case of reset, we will not wait!!
        (upstream.done() && downstream.done());
}

auto session::info() const -> std::string {
    if (empty()) {
        return "no captures";
    }
    std::ostringstream formatter;
    if (!upstream.no_control()) {
        formatter << "downstream: " << upstream.connection_id();
    }
    if (!downstream.no_control()) {
        formatter << "/upstream: " << downstream.connection_id();
    } else {
        formatter <<", no replies";
    }
    return formatter.str();
}

auto session::lifetime() const -> data_flow::timestamp_t {
    return empty() ? 0 : std::max(upstream.lifetime(), downstream.lifetime());
}

auto session::upstream_size() const -> std::size_t {
    return upstream.data_size();
}

auto session::downstream_size() const -> std::size_t {
    return downstream.data_size();
}

auto session::not_ready_size() const -> bool {
    return upstream_size() == 0 || downstream_size() == 0;
}

auto session::payloads_memory() const -> std::size_t {
    return upstream_size() + downstream_size();
}

auto session::take() -> session_payload {
    session_payload ret{std::move(upstream.take()), std::move(downstream.take()), is_partial()};
    verify_keep_alive();
    return ret;
}

auto take_if(session& s) -> std::optional<session_payload> {
    bool ready = s.ready();
    bool done = s.done();
    if (ready || done) {
        return s.take();
    }
    return std::nullopt;    // we are not ready yet..
}

auto session::print(std::ostream& os) const -> std::ostream& {
    if (empty()) {
        return os << "empty";
    }
    os<<"\n=================================\n\t\tupstream:\n---------------------------------\n\t\t";
    os << upstream;
    os<<"\n=================================\n\t\tdownstream:\n---------------------------------\n\t\t";
    os << downstream;
    return os<<"\n=================================\n";
}

auto operator << (std::ostream& os, const session& s) -> std::ostream& {
   return s.print(os);
}

auto operator << (std::ostream& os, const session::flows& flows) -> std::ostream& {
    if (!flows.control().empty()) {
        os << "control flows:\n\t" << flows.control() <<  "\n\t\t";
    } else {
        os << "no control flows\n";
    }
    if (!flows.data().empty()) {
        os << "data flows:\n\t" << flows.data()<< "\n\t\t";
    } else {
        os << "no data flows\n";
    }
    return os;
}

auto handle_session_overflow = [count = 0lu](auto it, auto&& new_flow, auto cur_payload, auto new_payload_size, auto default_ret) mutable {
    if ((count++ % 1'000) == 0) {
        LOG_HTTP_PACKETS_DEBUG << "for the " << count << " we have rate limit for session: memory used: " 
            << cur_payload << " and it required " << new_payload_size 
            << ", discard " << new_flow.ipv4_layer << "/" << new_flow.tcp_layer;
    }
    
    if (parser::is_http_request_start(new_flow.str()) && it->try_insert(std::move(new_flow))) {
        return it;
    }
    it->marked_partial();
    return default_ret;
};


auto flows_stream::reorder() -> void {
    std::stable_sort(begin(), end(), [](auto&& left, auto&& right) {
        return left.tcp_layer.sequence_num < right.tcp_layer.sequence_num;
    });
}

auto flows_stream::as_string() -> std::string {
    if (!empty()) {
        reorder();
        auto s = data_size();
        std::string res;
        res.reserve(s);
        return std::accumulate(data.begin(), data.end(), res, [](auto&& str, auto&& d) {
            return str + d.payload_2_string();
        });
    }
    return {};
}

auto flows_stream::data_size() const -> std::size_t {
    return calculate_payloads(data);
}


auto sessions_repo::add_flow(data_flow new_flow) -> sessions_t::iterator {
    if (new_flow.control_only()) {
        return end();
    }
    const auto id = make_id(new_flow);
    auto it = sessions.find(id);
    if (it != end()) {
        // check memory budget
        auto new_payload_size = new_flow.payload_size();
        if (new_payload_size > 0) {
            auto cur_payload = it->second.payloads_memory();
            if ((cur_payload + new_payload_size) > rate_limit_session) {
                if (parser::is_http_request_start(new_flow.str()) && it->second.try_insert(std::move(new_flow))) {
                    return it;
                }
                it->second.marked_partial();
                return end();
            }
        }
        const auto b = it->second.try_insert(std::move(new_flow));
        if (b) {
            return it;
#ifdef DEBUG_SESSION_FLOW
        } else {
            LOG_HTTP_PACKETS_WARN << "failed to add packet to entry " << it->info() << ": " << b.error_value();
#endif      // DEBUG_SESSION_FLOW
        }
    } else {
        if (auto new_session = make_new_session(std::move(new_flow)); new_session) {
            auto ret = sessions.emplace(id, new_session.value());
            return ret.first;
        }
    }
    return end();
}

}   // end of namespace monitor
