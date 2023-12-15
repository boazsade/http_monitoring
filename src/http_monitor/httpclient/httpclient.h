#pragma once

#include <string>
#include <string_view>
#include <vector>

namespace boost { namespace asio {
class io_context;
}}

using http_header = std::pair<std::string, std::string>;
using headers_t = std::vector<http_header>;
// Create and run HTTP client that sends a HTTP message
// to the remote server and then dies
auto run_http_client(boost::asio::io_context& ioc, std::string host, const std::string& api_path, 
    std::uint16_t port, headers_t headers, std::string payload) -> void;
