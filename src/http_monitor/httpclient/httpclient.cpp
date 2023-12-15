#include "httpclient.h"
#include "Log/logging.h"
#include <boost/asio.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/algorithm/string.hpp>
#include <chrono>
#include <cstdlib>
#include <functional>
#include <iostream>

namespace beast = boost::beast;         // from <boost/beast.hpp>
namespace http = beast::http;           // from <boost/beast/http.hpp>
namespace net = boost::asio;            // from <boost/asio.hpp>
using tcp = boost::asio::ip::tcp;       // from <boost/asio/ip/tcp.hpp>

namespace 
{

struct connection {
    std::string_view host;
    std::uint16_t port = 0;

    constexpr connection(std::string_view h, std::uint16_t p) : host{h}, port{p} {

    }
};

enum FailedError {
    RESOLVE = 0,
    CONNECT,
    WRITE,
    READ,
    CLOSE,
    IGNORE
};

auto to_string(FailedError from) -> const char* {
    switch (from) {
        case FailedError::CLOSE:
            return "close";
        case FailedError::CONNECT:
            return "connect";
        case FailedError::READ:
            return "read";
        case FailedError::RESOLVE:
            return "resolve";
        case FailedError::WRITE:
            return "write";
        case FailedError::IGNORE:
            return "no error";
        default:
            return "unknown error";
    }
}

auto operator << (std::ostream& os, connection c) -> std::ostream& {
    return os << "host: " << c.host << ":" << c.port;
}

using reasons_map = std::array<std::uint64_t, std::size_t(IGNORE)>;

auto network_failure = [reasons = reasons_map{}, count = 0lu](FailedError err) mutable {
    static const std::uint64_t threshold = 10'000;
    reasons[err]++;
    if ((reasons[err] % threshold) == 0) {
        LOG_HTTP_PACKETS_WARN << "we have " << number_printer<std::size_t>(reasons[err]) << " HTTP network errors for " << to_string(err);
    }
};

auto fail(beast::error_code ec, FailedError what, connection con) -> void {
    LOG_HTTP_PACKETS_INFO << con << " error " << to_string(what) << ": " + ec.message();
    if (what != FailedError::READ && what != FailedError::IGNORE) {    // we can live without this
        network_failure(what);
    }
}


auto post_http_msg(std::string_view host, std::uint16_t port, const std::string& api_path,
    headers_t headers, std::string_view payload, net::io_context& ioc, net::yield_context yield) -> void {

    static const std::string_view host_header = "host";
    constexpr int http_protocol_version_1_1 = 11;
    constexpr std::string_view content_type_value = "application/json";

    const std::string target_host{host};
    beast::error_code ec;

    tcp::resolver resolver(ioc);
    beast::tcp_stream stream(ioc);

    auto const results = resolver.async_resolve(host, std::to_string(port), yield[ec]);
    if (ec) {
        return fail(ec, FailedError::RESOLVE, connection{target_host, port});
    }
    stream.expires_after(std::chrono::seconds(30));

    auto defer = [&](auto err) -> void {
         // Gracefully close the socket
        stream.socket().shutdown(tcp::socket::shutdown_both, ec);
        return fail(ec, err, connection{target_host, port});
    };
    // Make the connection on the IP address we get from a lookup
    stream.async_connect(results, yield[ec]);
    if (ec) {
        return defer(FailedError::CONNECT);
    }

    
    // Set up an HTTP request message
    http::request<http::string_body> req{payload.empty() ? http::verb::get : http::verb::post, api_path, http_protocol_version_1_1};
    req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
        // set the headers
    for (const auto& h : headers) {
        if (h.first != host_header) {
            req.insert(h.first, h.second);
        } else {
            req.insert(http::field::host, h.second);
        }
    }
    // if we have a body, handle it here
    if (!payload.empty()) {
        //std::string body = "hello world";
        req.set(http::field::content_length, std::to_string(payload.size()));
        req.set(http::field::content_type, std::string(content_type_value));
        
        req.body() = payload;
        req.prepare_payload();
    }
    // Set the timeout.
    stream.expires_after(std::chrono::seconds(30));

    // Send the HTTP request to the remote host
    http::async_write(stream, req, yield[ec]);
    if (ec) {
        return defer(FailedError::WRITE);
    }

    // This buffer is used for reading and must be persisted
    beast::flat_buffer b;

    // Declare a container to hold the response
    http::response<http::dynamic_body> res;

    // Receive the HTTP response, we don't really doing match with it
    // but we want to do a cleanup to the other side
    http::async_read(stream, b, res, yield[ec]);
    if (ec) {
        return defer(FailedError::IGNORE);
    }
   
    // not_connected happens sometimes
    // so don't bother reporting it.
    LOG_HTTP_PACKETS_DEBUG << "successfully sent message of size " <<
                payload.size() << " to host " << host <<
                " at resource (" << api_path << "), and port " << std::to_string(port);
    return defer(FailedError::IGNORE);
}

}   // end of local namespace

auto run_http_client(net::io_context& ioc, std::string host, const std::string& api_path, 
    std::uint16_t port, headers_t headers, std::string payload) -> void {
    boost::asio::spawn(ioc, std::bind(
            &post_http_msg,
            host, port,
            api_path, headers,
            payload, std::ref(ioc),
            std::placeholders::_1)
    );
}

