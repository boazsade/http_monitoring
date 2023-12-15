#pragma once

#include "session.h"
#include "results.h"
#include "channel.h"
#include <thread>
#include <string>
#include <iosfwd>
#include <vector>
// This is the entry point to the network packet monitoring
// In here we are setting up the pcap lib for the live capture
// then we are running it.
// Since we need to save states between the packets and we need to
// save the sessions this has a utility class that holds this state
struct pcap_pkthdr;
struct pcap;

namespace monitor
{

using filter_type = const char*;
using interface_id = const char*;

constexpr std::uint64_t MB2BYTES = 1024 * 1024;
constexpr std::uint64_t GB2BYTES = MB2BYTES * 1024;
constexpr int IPV6_HEADER = 40;
constexpr int DEFAULT_CAPTURE_SIZE                  = 0xffff + IPV6_HEADER + ethernet_header_len();
constexpr int DEFAULT_CAPTURE_TIMEOUT_MILLISECONDS  = 1000;         // libpcap timeout value
constexpr std::uint64_t DEFAULT_MAX_MEMORY = 0xffffffff; // no limit
constexpr std::uint64_t DEFAULT_MAX_MESSAGE = 100 * MB2BYTES;

class network_capture 
{
public:
    using session_repo_t = sessions_repo;
    struct config 
    {
        interface_id device = nullptr; 
        filter_type filter = nullptr; 
        std::uint64_t max_memory = DEFAULT_MAX_MEMORY;
        std::uint64_t max_session_payload = DEFAULT_MAX_MESSAGE;
        int capture_size = DEFAULT_CAPTURE_SIZE;
        int timeout = DEFAULT_CAPTURE_TIMEOUT_MILLISECONDS;
        bool promiscuous_mode = false;
        std::vector<std::uint16_t> ports;

        config(interface_id dev, filter_type f,
            std::uint64_t mm, std::uint64_t ms, bool promisc,
            std::vector<std::uint16_t> p,
            int cs = DEFAULT_CAPTURE_SIZE, int to = DEFAULT_CAPTURE_TIMEOUT_MILLISECONDS) :
                device{dev}, filter{f}, max_memory{mm}, max_session_payload{ms},
                capture_size{cs}, timeout{to}, 
                promiscuous_mode{promisc && dev != ANY_DEVICE},
                ports{std::move(p)} {
        }
    };

    network_capture(default_write_channel ch) : monitor{ch} {
    }
    
    //  disable copy/assign operator! but this can be moved
    network_capture(const network_capture&) = delete;
    network_capture& operator = (const network_capture&) = delete;
    // set a new interface, filter, capture size and timeout value and run a new capture
    // Precondition: running() == false
    // return true if we have valid device name, filter and we were able to start the capture lib
    [[nodiscard]] auto run(config conf) -> result<bool, std::string>;

    // return true if we successfully capture some packets. This means that some packets are 
    // passing the filter predicate
    [[nodiscard]] auto has_data() const -> bool {
        return sessions() != 0;
    }

    [[nodiscard]] auto sessions() const -> std::size_t {
        return monitor.sessions();
    }

    [[nodiscard]] auto live_sessions() const -> const session_repo_t& {
        return monitor.live_data();
    }

    // stop running the capture. 
    // post condition -> the number of sessions don't change any more
    // return false if not running any more, please not that this will sync
    // to the working thread
    auto stop() -> bool;

    // return true if the working thread is running
    [[nodiscard]] constexpr auto running() const -> bool {
        return monitor.running();
    }

    auto mem_usage() const -> std::uint64_t {
        return monitor.mem_usage();
    }

    // This is the handle that we are passing to the capture callback
    // in libpcap
    struct monitor_handler
    {
        using session_iter = session_repo_t::sessions_t::iterator;

        static const std::size_t INTERNAL_CHANNEL_SIZE = 4096;
        using internal_channel = channel<data_flow, INTERNAL_CHANNEL_SIZE>;
        using write_channel = write_only_channel<internal_channel::element_type, INTERNAL_CHANNEL_SIZE>;
        using read_channel = read_only_channel<internal_channel::element_type, INTERNAL_CHANNEL_SIZE>;

        struct memory_usage
        {
            std::atomic_uint64_t total_memory_usage = 0;
            std::atomic_uint64_t max_allow_mem = DEFAULT_MAX_MEMORY;

            memory_usage() = default;

            auto start(std::uint64_t max_mem) -> void;

            auto mem_usage() const -> std::uint64_t {
                return total_memory_usage;
            }

            auto threshold() const -> std::uint64_t {
                return max_allow_mem;
            }

            auto operator -= (std::uint64_t count) -> memory_usage& {
                total_memory_usage -= count;
                return *this;
            }

            auto operator += (std::uint64_t count) -> memory_usage& {
                total_memory_usage += count;
                return *this;
            }

            auto will_overflow(std::uint64_t count) const -> bool {
                return (count + total_memory_usage) > max_allow_mem;
            }
        };
        struct network_device
        {

            explicit network_device(memory_usage* c, internal_channel ch) : output_channel{ch}, mem_counters{c} {
            }

            ~network_device() {
                stop();
            }
             
            auto stop() -> bool;

            auto startup(pcap* ph, std::string_view dev) -> bool;

            auto setup(pcap* ph, std::string_view dev) -> bool;

            auto run() -> void;

            [[nodiscard]] constexpr auto running() const -> bool {
                return work;
            }
            
            auto count_drop() -> void {
                dropped_packets++;
            }
            auto count_success() -> void {
                success_packets++;
            }

            [[nodiscard]] auto process(const struct pcap_pkthdr* header, const std::uint8_t* packet) -> result<bool, std::string>;

            [[nodiscard]] auto try_from(const struct pcap_pkthdr* header, const std::uint8_t* packet) const -> result<internal_channel::element_type, std::string>;

            auto capture() -> bool;

            constexpr auto handle() -> pcap* {
                return pcap_handler;
            }

        private:
            [[nodiscard]]auto process_it(const struct pcap_pkthdr* header, const std::uint8_t* packet) -> result<bool, std::string>;
            [[nodiscard]] auto parse(const std::uint8_t* packet, const struct pcap_pkthdr* header) -> result<bool, std::string>;

        private:
            std::size_t         dropped_packets = 0;
            std::size_t         success_packets = 0;
            pcap*               pcap_handler = nullptr;
            std::size_t         ether_offset = ethernet_header_len();
            std::thread         worker;
            write_channel       output_channel;
            memory_usage*       mem_counters = nullptr;
            bool                work = false;
        };

        struct sessions_device
        {
            sessions_device(memory_usage* c, 
                internal_channel ch,
                default_write_channel oc) : 
                    input_channel{ch}, mem_counters{c}, write_channel{oc} {

            }

            ~sessions_device() {
                stop();
            }
             
            auto stop() -> bool;

            [[nodiscard]] constexpr auto running() const -> bool {
                return work;
            }

            auto startup(std::uint64_t max_msg, const std::vector<std::uint16_t>& p) -> bool;

            auto run() -> void;

            auto setup(std::uint64_t max_msg, const std::vector<std::uint16_t>& p) -> void;

            [[nodiscard]] constexpr auto live_data() const -> const session_repo_t& {
                return live_flows;
            }

            auto process(internal_channel::element_type flow) -> session_iter;
            auto send_ready(session_iter last_processed) -> void;

        private:
            auto do_work() -> void;

            auto run_gc() -> void;

            auto free_space() -> void;
            auto send_session(session_payload&& last_processed) -> void;

        private:
            

            session_repo_t       live_flows;
            read_channel        input_channel;
            memory_usage*       mem_counters = nullptr;
            std::thread         worker;
            bool                work = false;
            default_write_channel  write_channel;
            std::vector<std::uint16_t> ports;
            std::vector<std::uint64_t> ignore_address;
        };

        monitor_handler(default_write_channel ch) : 
            pcap_handler{nullptr}, flows_channel{}, mem_counters{},
            networking_task{&mem_counters, flows_channel}, sessions_task{&mem_counters, flows_channel, ch} {
        }

        ~monitor_handler() {
            stop();
        }

        auto start(pcap* ph, std::uint64_t max_mem, std::uint64_t max_msg, std::string_view dev,
            const std::vector<std::uint16_t>& ports) -> void;

        [[nodiscard]] constexpr auto handle() -> pcap* {
            return pcap_handler;
        }

        [[nodiscard]] auto sessions() const -> std::size_t {
            return live_data().saved();
        }

        auto stop() -> bool {
            return networking_task.stop() && sessions_task.stop();
        }

        [[nodiscard]] constexpr auto running() const -> bool {
            return networking_task.running() || sessions_task.running();
        }

        [[nodiscard]] constexpr auto live_data() const -> const session_repo_t& {
            return sessions_task.live_data();
        }

        auto mem_usage() const -> std::uint64_t {
            return mem_counters.mem_usage();
        }

private:
        pcap*               pcap_handler = nullptr;
        internal_channel    flows_channel;
        memory_usage        mem_counters;
        network_device      networking_task;
        sessions_device     sessions_task;
    };

private:
    //auto do_work() -> void;

private:
    monitor_handler monitor;
};

// we can ensure that we have a valid device for this capture
[[nodiscard]] auto validate_interface(interface_id device_name) -> result<bool, std::string>;

// make sure that the filter we have is valid
[[nodiscard]] auto validate_filter(filter_type filter, interface_id device_name = nullptr) -> result<bool, std::string>;

auto operator << (std::ostream& os, const network_capture::monitor_handler::memory_usage& mem) -> std::ostream&;


}   // end of namespace monitor
