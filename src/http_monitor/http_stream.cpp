#include "http_stream.h"
#include "results.h"
#include "Log/logging.h"
#include "http_match.h"
#include "utils.h"
#include <boost/circular_buffer.hpp>
#include <boost/algorithm/string/find.hpp>
#include <boost/asio.hpp>
#include <thread>


namespace monitor
{

namespace
{
namespace ip = boost::asio::ip;

enum ReadError {
    ERROR_TRIES,
    ERROR_IO
};

using namespace std::string_literals;

constexpr std::size_t MAX_HISTORY = 8 * 1'1024; // 8k of messages we are allowing to send
using messages_t = boost::circular_buffer<http_stream::message_type>;
using http_header = std::pair<std::string, std::string>;
using headers_t = std::vector<http_header>;

constexpr std::string_view DELIMITER = "\r\n";
constexpr std::string_view EMPTY_LINE = "\r\n\r\n";

auto report_connection_errors = [count = 0lu] (auto h, auto p, auto err) mutable {
    if (err) {
        if ((count % 1'000) == 0) {
            LOG_HTTP_PACKETS_FATAL << "failed to connect for " << count <<" times to host " << h << ":" << p << ", error: " << err;
        }
        count++;
        return false;
    }
    LOG_HTTP_PACKETS_INFO << "successfully connect to host " << h << ":" << p;
    return true;
};

auto report_on_exception_err = [count = 0lu] (auto h, auto p, auto err) mutable {
    if ((count % 1000) == 0) {
        LOG_HTTP_PACKETS_ERR << "while trying to connect HTTP client to " << h << ":" << p << " - got an " << count << " times error: " << err.what();
    }
    count++;
    return false;
};

auto report_on_response_err = [count = 0lu] (auto err) mutable {
    if ((count % 1'000) == 0) {
        LOG_HTTP_PACKETS_FATAL << "while reading message from remote server got unrecoverable error for " << count << " times: " << err.what();
    }
    count++;
    return false;
};

auto report_request_err = [count = 0lu] (auto err, auto url) mutable {
    if ((count % 1'000) == 0) {
       LOG_HTTP_PACKETS_FATAL << "while sending request to remote host at " << url << " got unrecoverable error for " << count << " times : " << err.what();
    }
    count++;
    return false;
};

auto connect(std::string_view host_address, std::string_view port, boost::asio::io_context& context, ip::tcp::socket& endpoint) -> bool {
     try {
        endpoint.close();
        ip::tcp::resolver resolver(context);
        auto endpoints = resolver.resolve(host_address, port);
        boost::system::error_code err;
        boost::asio::connect(endpoint, endpoints, err);
        return report_connection_errors(host_address, port, err);
    } catch (const boost::system::system_error& er) {
        return report_on_exception_err(host_address, port, er);
    } catch (const std::exception& e) {
        return report_on_exception_err(host_address, port, e);
    }
}

auto read_headers = [](auto max_tries, auto& stream) -> result<std::string, ReadError>  {
    std::string header;
    while (max_tries-- > 0) {
        if (!std::getline(stream, header)) {
            return failed(ReadError::ERROR_IO);
        }
        if (header != "\r") {
            return ok(header);
        } else {
            return ok(std::string{});
        }
    }
    return failed(ReadError::ERROR_TRIES);
};

auto read_response(ip::tcp::socket& socket) -> bool {
    static const std::string PERSIST_CONNECTION_HEADER_KEY = "Connection";
    static const std::string NOT_PERSIST_VALUE = "close";
    constexpr std::size_t MIN_RESPONSE_LINE = 16;
    constexpr std::size_t MIN_HEADERS_SIZE = 64;
    constexpr std::size_t MAX_HEADERS_TRIES = 20;
    constexpr int MAX_BODY_TRIES = 10;

    auto read_until = [&](auto max_tries, auto min_bytes, auto& res, auto delim) {
        boost::system::error_code error;
        
        for (std::size_t s = 0; s < min_bytes && max_tries > 0; --max_tries) {
            s = boost::asio::read_until(socket, res, delim, error);
            if (error) {
                if (error == boost::asio::error::would_block) {
                    std::this_thread::yield();
                } else {
                    return false;
                }
            }
        }
        return max_tries != 0;
    };

    try {
        boost::asio::streambuf response;
        // return response line
        if (!read_until(5, MIN_RESPONSE_LINE, response, DELIMITER)) {
            return false;
        }
        std::istream response_stream(&response);
        std::string status_line;
        response_stream >> status_line;
        if (!parser::is_http_response_start(status_line)) {
            return false;
        }
        // read all the headers
        if (!read_until(5, MIN_HEADERS_SIZE, response, EMPTY_LINE)) {
            return false;
        }
        // Process the response headers.
        bool persist_connection = true;
        for (auto header = Ok(read_headers(MAX_HEADERS_TRIES, response_stream)); header; header = Ok(read_headers(MAX_HEADERS_TRIES, response_stream))) {
            if (boost::algorithm::ifind_first(*header, PERSIST_CONNECTION_HEADER_KEY) &&
                boost::algorithm::ifind_last(*header, NOT_PERSIST_VALUE)) {
                   persist_connection = false; 
            }
        }
        
        // Read until EOF, writing data to output as we go.
        boost::system::error_code error;
        
        auto tries = MAX_BODY_TRIES;
        while (boost::asio::read(socket, response, boost::asio::transfer_at_least(0), error) != 0 && tries > 0) {
            if (error) {
                if (error != boost::asio::error::would_block) {
                    return false;
                }
                --tries;
            }
        }
        
        if (error || tries == 0) {
            return false;
        }
        
        return persist_connection;
    } catch (const boost::system::system_error& er) {
        return report_on_response_err(er);
    } catch (const std::exception& e) {
        return report_on_response_err(e);
    }
}

auto http_request(ip::tcp::socket& socket, std::string_view url, std::string body, headers_t headers) -> bool {
    constexpr const char* METHODS[] = {
        "POST", "GET"
    };
	constexpr int MIN_SIZE = 3;	// length of GET string
    constexpr int MAX_TRIES = 20;
    boost::asio::streambuf request;
    try {
        std::ostream request_stream(&request);
        request_stream << METHODS[body.empty()] << " " << url << " HTTP/1.1" << DELIMITER;
        for (auto&& [k, v] : headers) {
            request_stream << k << ": " << v << DELIMITER;
        }
        request_stream << "Accept: */*" << DELIMITER;
        request_stream << "User-Agent: Ammune,ai Packet Monitor" << DELIMITER;
        request_stream << "Content-Type: application/json" << DELIMITER;
        request_stream << "Content-Length: " << body.size() << DELIMITER;
        request_stream << "Connection: keep-alive" << EMPTY_LINE;
        if (!body.empty()) {
            request_stream << body;
        }
        boost::system::error_code error;
        std::size_t s = 0;
        auto tries = MAX_TRIES;
        while (s < MIN_SIZE && tries-- > 0) {
            s = boost::asio::write(socket, request, error);
            if (s < MIN_SIZE || error == boost::asio::error::would_block) { // not all was sent
                std::this_thread::yield();      // if there are other threads on this CPU, let them run now
            } else if (error) {
                return false;
            } else {
                return true;
            }
        }
        return tries > 0;
    } catch (const boost::system::system_error& er) {
        return report_request_err(er, url);
    } catch (const std::exception& e) {
        return report_request_err(e, url);
    }
}

auto post_messages(messages_t&& messages, const std::string& host, const std::string& port, std::string_view api) -> result<std::size_t, std::string> {
    constexpr std::string_view REQUEST_ID_HEADER = "x-request-id";
    const std::string REMOTE_HOST_URI = "/ammune/log";
    constexpr std::string_view HOST_HEADER = "Host";

    boost::asio::io_context context;
    ip::tcp::socket         endpoint{context};

    if (!connect(host, port, context, endpoint)) {
        return failed("failed to open connection to "s + host + ":" + port);
    }
    auto count = 0lu;
    for (auto&& msg : messages) {
        headers_t headers {
            http_header{REQUEST_ID_HEADER, msg.uuid},
            http_header{HOST_HEADER, msg.host},
            http_header{HOST_HEADER, host + ":"s + port}
        };
        if (!http_request(endpoint, api, std::move(msg.payload), std::move(headers))) {
            if (!connect(host, port, context, endpoint)) {
                return failed("lost connection while in sending requests"s);
            }
        }
        if (!read_response(endpoint)) {
            if (!connect(host, port, context, endpoint)) {
                return failed("lost connection while in reading response"s);
            }
        }
        ++count;   
    }
    
    return ok(count);
}

}   // end of local namespace


auto http_stream::stop() -> void {
    run = false;
    if (context.joinable()) {
        // we must make sure that we can cancel the connection
        context.join();
    }
}

auto http_stream::start(std::string_view h, std::uint16_t p) -> bool {
    host = h;
    port = std::to_string(p);
    failures = 0;
    successful = 0;
    run = true;
    context = std::thread([this]() {
            this->work();
    });
    utils::rename_thread(context, std::string{"http-" + port}.c_str());
    return true;
}

auto http_stream::post(message_type msg) -> bool {
    return channel.push(std::move(msg));
}

auto http_stream::work() -> void {
    constexpr std::string_view REMOTE_HOST_URI = "/ammune/log";
    constexpr std::uint32_t MAX_DELAY_TRIES = 10;
    constexpr std::size_t   MIN_TO_SEND = 20;
    constexpr std::size_t PAUSE_TIME_NO_DATA = 2;
    constexpr std::size_t PAUSE_TIME_FAILS = 6;

    auto sender = [host = this->host, port = this-> port, tries = MAX_DELAY_TRIES, remote_api = REMOTE_HOST_URI] (messages_t& messages) mutable {
        if (messages.empty()) {
            tries = MAX_DELAY_TRIES;
            return 0;
        }
        if (messages.size() >= MIN_TO_SEND || tries == 0) {
            auto size = int(messages.size());               
            tries = MAX_DELAY_TRIES;
            auto res = post_messages(std::exchange(messages, messages_t(MAX_HISTORY)), host, port, remote_api);
            if (res.is_error()) {
                return size * -1;
            } else {
                return size;
            }
        } else {
            --tries;
            return 0;
        }
    };

    messages_t messages(MAX_HISTORY);
    while (run) {
        channel.consume_all([&messages](auto&& msg) {
            messages.push_back(std::move(msg));
        });
        auto s = sender(messages);
        if (s < 0) {
            failures += (s * -1);
            std::this_thread::sleep_for(std::chrono::milliseconds(PAUSE_TIME_FAILS));
        } else if (s > 0) {
            successful += s;
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(PAUSE_TIME_NO_DATA));
        }
    }
}

}   // end of namespace monitor
