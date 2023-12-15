#pragma once
#include "results.h"
#include "session.h"
#include "output_data.h"
#include "channel.h"
#include "http_stream.h"
#include <string>
#include <iostream>

namespace monitor
{

// This class will accept the session in raw format and will generate
// an output that can be used as an output to the last step which is
// the sink that will act that the final step in the processing
class output_formatter
{
public:
    enum errors_types {
        INVALID_SESSION,
        NOT_HTTP_MESSAGE,
        MISSING_DATA_TYPES
    };

    using input_type = session_payload;
    using output_type = output_data;

    output_formatter() = default;

    static auto transform(input_type input) -> result<output_type, errors_types>;
};

auto to_string(output_formatter::errors_types error) -> std::string;
inline auto operator << (std::ostream& os, output_formatter::errors_types error) -> std::ostream& {
    return os << to_string(error);
}

class formatter
{
public:
    struct counters
    {
        std::uint64_t success_format = 0;
        std::uint64_t failed_format = 0;
        std::uint64_t success_send = 0;
        std::uint64_t failed_send = 0;

        auto operator += (const counters& c) -> counters&;
    };

    formatter(std::size_t workers, std::uint32_t base_id, const std::string& host);
    ~formatter() {
        stop();
    }

    formatter(const formatter&) = delete;
    formatter& operator = (const formatter&) = delete;

    auto stop() -> void;

    auto consume(output_formatter::input_type input) -> bool;

    auto scrap_counters() const -> counters;

private:
    struct executer
    {
        auto start(std::uint16_t port, const std::string& host) -> bool;
        auto stop() -> bool;
        auto consume(output_formatter::input_type input) -> bool {
            return io.send(std::move(input));
        }

        auto scrap_counters() const -> counters;

    private:
        auto do_work(default_read_channel input) -> void;

        auto format_and_send(default_channel::element_type input) -> void;

    private:
        http_stream sender;
        std::thread worker;
        std::atomic_uint64_t success = 0;
        std::atomic_uint64_t failed = 0;
        default_channel io;
        bool work = false;
    };

    struct profiling_rate
    {
        std::chrono::time_point<std::chrono::steady_clock>  start;
        std::uint64_t count = 0;

        profiling_rate();

        auto report(const formatter& f) -> void;
    };

    using workers_t = std::vector<executer>;

    workers_t workers;
    std::uint32_t base_port = 0;
    profiling_rate rate;
    std::uint64_t seen = 0;
};

inline auto operator + (formatter::counters left, const formatter::counters& right) -> formatter::counters {
    left += right;
    return left;
}

}       // end of namespace monitor
