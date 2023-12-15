#pragma once
#include "results.h"
#include "channel.h"
#include "capture.h"
#include <thread>
#include <atomic>

namespace monitor
{

class formatter;
// This class is the main entry point to process the captures from the network
// However this is not where it all started, to make it less depends on external
// flows, it would accept the device on which to capture as well as the filter
// on which to work.
// On top of it would also have the remote host to which to send the output that
// it generate
class processor
{
public:
    static constexpr const char* LOCALHOST = "127.0.0.1";
    static constexpr std::uint16_t DEFAULT_TARGET_PORT = 8081;
    struct counters_info
    {
        using counter_type = std::atomic_ulong;

        counter_type active_sessions;
        counter_type successful_sent;
        counter_type completed_sessions;
        counter_type failure_count;
        counter_type failed_sent;
        counter_type sessions_count;

        auto reset() -> void;
    };

    ~processor();
    processor(const processor&) = delete;
    processor& operator = (const processor&) = delete;

    struct config
    {
        std::string         interface_name;
        std::string         filter;
        std::uint16_t       remote_port = DEFAULT_TARGET_PORT;
        std::uint16_t       remote_ports_count = 8;
        std::string         remote_host = LOCALHOST;
        std::uint64_t       max_memory = DEFAULT_MAX_MEMORY;    // in bytes
        std::uint64_t       max_payload_per_msg = DEFAULT_MAX_MESSAGE; // bytes
        bool                promiscuous_mode = false;
        std::vector<std::uint16_t>  port_list;

        config(const std::string& ifn, const std::string& f, 
                std::uint16_t rp, std::uint16_t rpc,
                const std::string& rh, float max_mem_gb,
                std::vector<std::uint16_t> p,
                std::uint32_t max_payload, bool promisc) :    // max payload in MB
                interface_name{ifn}, filter{f}, remote_port{rp}, remote_ports_count{rpc},
                remote_host{rh}, max_memory{std::uint64_t(max_mem_gb * GB2BYTES)},
                max_payload_per_msg{max_payload * MB2BYTES}, promiscuous_mode{promisc && ifn != ANY_DEVICE},
                port_list{std::move(p)} {
        }

        config(const std::string& ifn, const std::string& f, 
                std::uint16_t rp, std::uint16_t rpc,
                const std::string& rh) : config(ifn, f, rp, rpc, rh, (float(DEFAULT_MAX_MEMORY) / float(GB2BYTES)), {}, DEFAULT_MAX_MESSAGE, false) {
        }

    };

    processor();

    // start the monitoring process.
    // once we have a configuration, we can start monitoring.
    // If we have any issue while starting we would report it
    // with an Error result.
    // pre condition running() == false
    // post condition running() == true && capture_device.running() == true
    auto start(config conf) -> result<bool, std::string>;

    // stop the monitoring of the packets
    // post condition running() == false && capture_device.running() == false
    //  and it is safe to call start again
    auto stop() -> result<bool, std::string>;

    constexpr auto running() const -> bool {
        return run;
    }

public:
    counters_info       counters;   // you should access this directly as this is thread safe

private:
    auto run_consumer(config conf) -> void;
    auto format_and_send(default_channel::element_type session, formatter& target) -> void;

private:
    default_channel     internal_com;
    network_capture     capture_device;
    std::thread         consumer;
    bool                run = false;    // so we can contorl the thread lifetime
};

auto operator << (std::ostream& os, const processor::counters_info& counters) -> std::ostream&;
auto operator << (std::ostream& os, const processor::config& conf) -> std::ostream&;

auto to_string(const processor::counters_info& counters) -> std::string;
auto to_string(const processor::config& conf) -> std::string;

}       // end of namespace monitor
