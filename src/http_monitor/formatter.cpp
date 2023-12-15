#include "formatter.h"
#include "Log/logging.h"
#include "http_match.h"
#include "http_stream.h"
#include "httpparser/httprequestparser.h"
#include "httpparser/httpresponseparser.h"
#include "httpparser/request.h"
#include "httpparser/response.h"
#include "utils.h"
#include <boost/algorithm/string.hpp>
#include <sstream>
#include <random>
#include <numeric>
#include <cmath>
		
#define PROFILE_PACKETS
namespace monitor
{

using namespace std::string_literals;
namespace
{

using namespace std::string_literals;

constexpr auto order_and_reconstruct_payload = [] (auto& stream) -> std::string {
    // so that we are re-ordering the data, we will not mix something that we don't care about
    std::stable_partition(std::begin(stream), std::end(stream), [] (auto&& flow) {
        return parser::is_http_response_start(flow.str());
    });
    return stream.as_string();
};


auto debug_print_payload(const output_formatter::input_type& input) -> void {
#ifdef PRINT_PACKET_DETAILS
    constexpr auto print_payloads = [] (const auto& stream, auto& out_stream) {
        std::for_each(std::begin(stream), std::end(stream), [&out_stream, index = 0] (const auto& flow) mutable {
            if (flow.has_payload()) {
                out_stream << "-------------------------------------------------\n";
                out_stream <<"[" << index << "] TCP: " << flow.tcp_layer << ", Data:\n++++++++++++++++++++++\n" << std::string_view((const char*)flow.app_data.data(), flow.app_data.size()) << "\n";
            }
            ++index;
        });
    };

    constexpr auto payload_2_string = [print_payloads] (const auto& stream) -> std::string {
        std::ostringstream parser;
        print_payloads(stream, parser);
        return parser.str();
    };
    LOG_HTTP_PACKETS_DEBUG << "upstream data:\n" << payload_2_string(input.upstream);
    LOG_HTTP_PACKETS_DEBUG << "downstream data:\n" << payload_2_string(input.downstream);
#else
    (void)input;
#endif  // PRINT_PACKET_DETAILS
}

auto generate_id = [gen = std::mt19937_64{}, dis = std::uniform_int_distribution<uint64_t>{}] () mutable {
    return dis(gen);
};

auto generate_uuid(std::uint64_t from) -> std::string {
    std::stringstream stream;
    stream << std::hex << from;
    return stream.str();
}

using namespace httpparser;


auto lightweight_request_parser(const std::string& raw_msg) -> result<Request, std::string> {
    const auto parse_res = parser::TryFrom<parser::request_message>(raw_msg);
    if (parse_res.is_error()) {
        return failed(std::string(std::move(parse_res.error_value())));       // didn't work out well..
    }
    auto http_request = parse_res.unwrap();
    if (http_request.version !=  parser::http_message_base::VERSION_1 && http_request.version != parser::http_message_base::VERSION_1_1) {
        return failed("unsupported version read in the request"s);
    }
    Request output;
    output.versionMajor = 1;
    if (http_request.version == parser::http_message_base::VERSION_1) {
        output.versionMinor = 0;
    } else {
        output.versionMinor = 1;
    }
    for (auto&& h : http_request.headers) {
        Request::HeaderItem hdr;
        hdr.name = h.first;
        hdr.value = h.second;
        output.headers.emplace_back(hdr);
    }
    
    output.content.insert(output.content.begin(), http_request.body.begin(), http_request.body.end());
    output.method = parser::to_string(http_request.method);
    output.uri = http_request.URL;
    return ok(output);
}

auto lightweight_response_parser(const std::string& raw_msg) -> result<std::string, std::string> {
    const auto parse_res = parser::TryFrom<parser::response_message>(raw_msg);
    if (parse_res.is_error()) {
        return failed(std::string(std::move(parse_res.error_value())));       // didn't work out well..
    }
    auto http_response = parse_res.unwrap();
    if (http_response.version !=  parser::http_message_base::VERSION_1 && http_response.version != parser::http_message_base::VERSION_1_1) {
        return failed("unsupported version read in the response"s);
    }
    
    return ok("success response"s);
}



constexpr auto parse_message = [] (auto& stream, auto&& lightweight_parser) {
    // This function will try to parse a message (either request or response).
    // If this would fail, it would then try to run through a more elaborate operation
    // where it try to clean and re-order the flows
    // if this fails, it would just return a failure, but at least we tried ;)
    auto payload = stream.as_string();
    payload = order_and_reconstruct_payload(stream);
            // try the last parser as well
    auto parse_result = lightweight_parser(payload);
    return parse_result;
};

constexpr auto stringify = [](auto from, auto to) -> std::string {
    std::ostringstream output;
    std::copy(from, to, std::ostream_iterator<std::string>{output, "\n"});
    return output.str();
};

auto http_parsing_error_report = [count = 0lu](auto&& http_res, auto&& http_req, auto&& input) mutable {
    if (((count++) % 200 ) == 0) {
        LOG_HTTP_PACKETS_WARN <<
            "this is error number " << count << " for HTTP flow. error: request parsing: "
            << (http_req.is_error() ? to_string(http_req) : "good") << ", response parsing: "
            << (http_res.is_error() ? to_string(http_res) : "good")
            << ". failed: ";  
        debug_print_payload(input);
    }
};

}   // end of local namespace

auto output_formatter::transform(input_type input) -> result<output_type, errors_types> {
    if (input.empty()) {
        return failed(errors_types::INVALID_SESSION);
    }
    if (input.upstream.empty()) {
        return failed(errors_types::MISSING_DATA_TYPES);
    }
    if (input.downstream.empty()) {
        return failed(errors_types::MISSING_DATA_TYPES);
    }

    const auto http_req = parse_message(input.upstream, lightweight_request_parser);
    const auto http_res = parse_message(input.downstream, lightweight_response_parser);

    if (http_req.is_error() || http_res.is_error()) {
        // while we are expecting that this will only get valid messages,
        // the reality is that we are seeing things that are not valid
        // so lower the level of the log to info
        http_parsing_error_report(std::move(http_res), std::move(http_req), input);
        return failed(errors_types::NOT_HTTP_MESSAGE);
    }

    const auto request = http_req.unwrap();
    const auto http_response = http_res.unwrap();
    auto id = generate_id();
    const auto request_id = generate_uuid(id);


    auto hh = std::find_if(request.headers.begin(), request.headers.end(), [](auto&& header) {
        return boost::iequals(header.name, "host");
      }
    );
    auto host = hh == request.headers.end() ? std::string{} : hh->value;
    return ok(output_type{id, 
        request_id, host, 
        "this is the result"s
    });
}

auto to_string(output_formatter::errors_types error) -> std::string {
    switch (error) {
    case output_formatter::errors_types::INVALID_SESSION:
        return "invalid session was given to formatter"s;
    case output_formatter::errors_types::NOT_HTTP_MESSAGE:
        return "session is not valid HTTP message"s;
    case output_formatter::errors_types::MISSING_DATA_TYPES:
        return "message type missing critical entries"s;
    default:
        return "unknown";
    
    }
}

///////////////////////////////////////////////////////////////////////////////

formatter::formatter(std::size_t count, std::uint32_t base_id, const std::string& host) :
    workers(count), base_port{base_id} {
    
    // start the workers..
    std::uint16_t p = std::uint16_t(base_port);

    for (auto& w : workers) {
        w.start(p++, host);
    }
}

auto formatter::consume(output_formatter::input_type input) -> bool {
    seen++;
    auto index = seen % workers.size();
    rate.report(*this);
    return workers[index].consume(std::move(input));
}

auto formatter::stop() -> void {
    for (auto&& w : workers) {
        w.stop();
    }
}

auto formatter::scrap_counters() const -> counters {
    auto c = std::accumulate(workers.begin(), workers.end(), counters{}, [](auto&& cur, const auto& w ) {
        return cur + w.scrap_counters();
    });
    return c;
}

auto formatter::executer::start(std::uint16_t port, const std::string& host) -> bool {
    stop();
    
    if (!sender.start(host, port)) {
        LOG_HTTP_PACKETS_FATAL << "failed to start client to " << host << ":" << port;
        return false;
    }
    worker = std::thread([this]() {
        this->work = true;
        this->do_work(default_channel(this->io));
    });
    utils::rename_thread(worker, std::string("formatter-" + std::to_string(port)).c_str());
    return true;
}

auto formatter::executer::stop() -> bool {
    work = false;
    if (worker.joinable()) {
        sender.stop();
        worker.join();
    }
    return work;
}

auto formatter::executer::do_work(default_read_channel input) -> void {
    static const std::chrono::milliseconds no_work_timeout{5};

    while (work) {
        auto c = input.consume_all([this](auto&& session) {
            this->format_and_send(std::move(session));
        });
        if (c == 0) {
            std::this_thread::sleep_for(no_work_timeout);
        }
    }
}

auto report_format_error  = [count = 0lu](auto err) mutable {
    if ((++count % 10'000) == 0) {
        LOG_HTTP_PACKETS_WARN << "we have formatting error number " << count << ": " << err;
    }
};

auto formatter::executer::format_and_send(default_channel::element_type input) -> void {
    const auto r = output_formatter::transform(std::move(input));
    if (r.is_error()) {
        failed++; 
        report_format_error(r);
    } else {
        if (sender.post(r.unwrap())) {
            success++;
        } else {
            failed++;
        }
    }
}

auto formatter::executer::scrap_counters() const -> counters {
    counters c;
    c.failed_send = sender.fails();
    c.success_send = sender.success();
    c.success_format = success;
    c.failed_format = failed;
    return c;
}

auto formatter::profiling_rate::report(const formatter& ) -> void {
#ifdef PROFILE_PACKETS
    constexpr std::uint64_t REPORT_COUNT = 100'000;
    count++;
    const auto success = count > REPORT_COUNT;//f.seen > 0 && (f.seen % REPORT_COUNT) == 0;
    
    if (success) {
        //auto c = f.scrap_counters();
        //count = c.success_send - count;
        auto end = std::chrono::steady_clock::now();
        double ms = double(std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count());
        double s = ms / 1'000;
        LOG_HTTP_PACKETS_WARN << "we processed " << number_printer<std::uint64_t>(count) << " requests per " <<  number_printer<long>(long(ms)) 
            << " milliseconds ( " << number_printer<std::uint64_t>(std::uint64_t(double(count) / s)) << " per sec)";
        start = end;
        count = 0;
    }
#endif  // PROFILE_PACKETS
}

formatter::profiling_rate::profiling_rate() : start{std::chrono::steady_clock::now()} {

}

auto formatter::counters::operator += (const counters& c) -> counters& {
    success_format += c.success_format;
    failed_format += c.failed_format;
    success_send += c.success_send;
    failed_send += c.failed_send;
    return *this;
}

}       // end of namespace monitor
