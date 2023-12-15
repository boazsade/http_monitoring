#pragma once
#include "output_data.h"
#include <string_view>
#include <boost/lockfree/spsc_queue.hpp>
#include <boost/lockfree/policies.hpp>
#include <vector>
#include <thread>

namespace monitor
{

struct http_stream {

    using message_type = output_data;
    http_stream() = default;
    ~http_stream() {
        stop();
    }

    auto stop() -> void;

    auto start(std::string_view host_address, std::uint16_t port) -> bool;

    auto post(message_type msg) -> bool;

    auto success() const -> std::uint64_t {
        return successful;
    }
    auto fails() const -> std::uint64_t {
        return failures;
    }
private:
    auto work() -> void;

private:
    using channel_type = boost::lockfree::spsc_queue<message_type, boost::lockfree::capacity<2048>>;
    using counter_type = std::atomic_ullong;

    std::thread context;
    bool run = false;
    std::string host;
    std::string port;
    channel_type channel;
    counter_type successful = 0;
    counter_type failures = 0;
};

}   // end of namespace monitor