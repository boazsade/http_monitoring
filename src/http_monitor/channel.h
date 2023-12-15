#pragma once

#include "session.h"
#include <boost/lockfree/spsc_queue.hpp>
#include <boost/lockfree/policies.hpp>

namespace monitor
{

inline constexpr std::size_t DEFAULT_CHANNEL_SIZE = 2048;
// Use this as a mean to pass work between the capture task and the task
// that sends the output out
// NOTE: this will work with single consume and single producer
template<typename T = session_payload, const std::size_t Size = DEFAULT_CHANNEL_SIZE>
struct channel
{
    using element_type = T;
    using com_type = boost::lockfree::spsc_queue<element_type, boost::lockfree::capacity<Size>>;

    channel() : com{std::make_shared<com_type>()} {
    }

    auto send(element_type new_session) -> bool {
        return com->push(std::move(new_session));
    }

    // pass function like object (some lambda to process all available elements in the queue
    template<typename Func>
    auto consume_all(Func&& f) -> std::size_t {
        return com->consume_all(f);
    }

    auto empty() const -> bool {
         return no_input() && no_output();
    }

    auto no_input() const -> bool {
         return com->write_available() == 0;
    }

    auto no_output() const -> bool {
        return com->read_available() == 0;
    }

private:
    using data_type = std::shared_ptr<com_type>;    // so we can share the lifetime across threads
    data_type com;
};

template<typename T = session_payload, const std::size_t Max = DEFAULT_CHANNEL_SIZE>
struct write_only_channel 
{
    using element_type = typename channel<T, Max>::element_type;

    write_only_channel(channel<T, Max> ch) : dest{ch} {
    }

    auto send(element_type new_session) -> bool {
        return dest.send(new_session);
    }

    auto empty() const -> bool {
        return dest.no_output();
    }

private:
    channel<T, Max> dest;
};

template<typename T = session_payload, const std::size_t Max = DEFAULT_CHANNEL_SIZE>
struct read_only_channel 
{
    read_only_channel(channel<T, Max> ch) : source(ch) {
    }

    template<typename Func>
    auto consume_all(Func&& f) -> std::size_t {
        return source.consume_all(f);
    }

    auto empty() const -> bool {
        return source.no_input();
    }

private:
    channel<T, Max> source;
};

using default_channel = channel<>;
using default_read_channel = read_only_channel<>;
using default_write_channel = write_only_channel<>;

}       // end of namespace monitor
