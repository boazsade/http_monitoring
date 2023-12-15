#pragma once
#include "results.h"
#include <string_view>
#include <string>
#include <vector>
#include <iosfwd>

namespace monitor
{
namespace parser
{

auto is_http_response_start(std::string_view payload) -> bool;
auto is_http_request_start(std::string_view payload) -> bool;

template<typename T>
auto TryFrom(const std::string&) -> result<T, std::string>;

struct http_message_base
{
     using header_t = std::pair<std::string, std::string>;
    using headers_t = std::vector<header_t>;
    using body_t = std::string;

    enum Version {
        VERSION_1,
        VERSION_1_1,
        VERSION_2,
        VERSION_3,
        UNKOWN_VERSION
    };

    enum HeaderAdded {
        OK_ADDED,
        DONE_ADDING,
        FAILED_ADDING
    };

    bool    is_encrypted = false;   // HTTP or HTTPS
    Version version = Version::UNKOWN_VERSION;
    headers_t headers;
    body_t    body;

    http_message_base() = default;

    auto add_header(std::string hl) -> HeaderAdded;

protected:
    explicit http_message_base(std::string http_ver);
};

struct request_message : public http_message_base
{
    enum Method {
        GET,
        HEAD,
        POST,
        PUT,
        DELETE,
        CONNECT,
        OPTIONS,
        TRACE,
        PATCH,
        ERROR = 0xff
    };

    std::string URL;
    Method method = Method::ERROR;

    request_message() = default;

    constexpr auto have_body() const -> bool {
        switch (method) {
        case Method::POST:
        case Method::PUT:
            return true;
        default:
            return false;
        }
    }

    constexpr auto may_have_body() const -> bool {
        if (have_body()) {
            return true;
        }
        switch (method) {
        case Method::TRACE:
            return false;
        default:
            return true;
        }
    }

    constexpr auto response_have_body() const -> bool {
        switch (method) {
        case Method::HEAD:
            return false;
        default:
            return true;
        }
    }
    static auto try_from(const std::string& from) -> result<request_message, std::string>;

private:
    request_message(std::string m, std::string url, std::string http_ver);
};
// try to parse the string into request
// note that this is a very basic parsing we are not really
// doing match validation, use in extreme cases
template<>
inline auto TryFrom<request_message>(const std::string& from) -> result<request_message, std::string> {
    try {
        return request_message::try_from(from);
    } catch (const std::exception& e) {
        return failed("critical error while converting message from input size of " + std::to_string(from.size()) + " into HTTP request: " + e.what());
    }
}


struct response_message : public http_message_base
{
    int status_code = 0;

    constexpr auto info() const -> bool {      // refers to status 
	return status_code >= 100 && status_code < 200;
    }
    constexpr auto success() const -> bool {   // refers to status code
    	return status_code >= 200 && status_code < 300;
    }
    constexpr auto redirect() const -> bool {  // refers to status code
    	return status_code >= 300 && status_code < 400;
    }
    constexpr auto client_error() const -> bool {    // refers to status code
    	return status_code >= 400 && status_code < 500;
    }
    constexpr auto server_error() const -> bool {  // refers to status code
    	return status_code >= 500 && status_code < 600;
    }

    response_message() = default;

    static auto try_from(const std::string& from) -> result<response_message, std::string>;
private:
    response_message(std::string s, std::string http_ver) : 
        http_message_base{std::move(http_ver)}, status_code{std::stoi(s)} {
    }
};
// try to parse the string into response
// note that this is a very basic parsing we are not really
// doing match validation, use in extreme cases
template<>
inline auto TryFrom<response_message>(const std::string& from) -> result<response_message, std::string> {
    try {
        return response_message::try_from(from);
    } catch (const std::exception& e) {
        return failed("critical error while converting message from input size of " + std::to_string(from.size()) + " into HTTP response: " + e.what());
    }
}

auto operator << (std::ostream& os, http_message_base::Version v) -> std::ostream&;
auto operator << (std::ostream& os, const http_message_base& msg) -> std::ostream&;
auto operator << (std::ostream& os, request_message::Method m) -> std::ostream&;
auto operator << (std::ostream& os, const request_message& msg) -> std::ostream&;
auto operator << (std::ostream& os, const response_message& msg) -> std::ostream&;
auto to_string(request_message::Method m) -> std::string;

}   // end of namespace parser
}   // end of namespace monitor