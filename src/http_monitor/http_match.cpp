#include "http_match.h"
#include "Log/logging.h"
#include <boost/algorithm/string.hpp>
#include <numeric>
#include <iostream>
#include <sstream>

namespace monitor
{
namespace parser
{
using namespace std::string_literals;
namespace
{

const std::string_view HTTP_DELIMITER = "\r\n";
const std::string_view HTTP_HEADERS_END = "\r\n\r\n";
const std::string HEADER_LIMITER = ":";
constexpr std::string_view FIRST_WORD_RESPONSE = "HTTP";
constexpr int DIGITS_STATUS_CODE = 3;
 constexpr std::size_t MIN_STATUS_LINE_ENTRIES = 3;
 constexpr int MAX_HEADERS = 100;

auto tokenize_string(std::string input, const char* delim) -> std::vector<std::string> {
    std::vector<std::string> output;
    boost::split(output, input, boost::is_any_of(delim));
    return output;
}

constexpr std::string_view METHODS[] = {
	"GET",	"DELETE", "CONNECT", "HEAD", "TRACE", 
	"OPTIONS", "PATCH", "POST", "PUT",
};

const std::pair<std::string_view, request_message::Method> METHOD_2_TYPE[] = {
        {METHODS[0], request_message::Method::GET},
        {METHODS[1], request_message::Method::DELETE},
        {METHODS[2], request_message::Method::CONNECT},
        {METHODS[3], request_message::Method::HEAD},
        {METHODS[4], request_message::Method::TRACE},
        {METHODS[5], request_message::Method::OPTIONS},
        {METHODS[6], request_message::Method::PATCH},
        {METHODS[7], request_message::Method::POST},
        {METHODS[8], request_message::Method::PUT}
};

auto extract_url(const std::vector<std::string>& tokens) -> std::string {
    // the first token is the method name, and the last is the version, all the others are part of the url
    switch (tokens.size()) {
        case 0:
        case 1:
        case 2:
            return {};
        case MIN_STATUS_LINE_ENTRIES:
            return tokens[1];
        default:
            break;
    }
    auto url = std::accumulate(std::next(std::begin(tokens)), std::prev(std::end(tokens)), std::string{}, [](auto&& v, auto&& t) {
        return v + ' ' + t; // need to keep the original spaces
    });
    return url;
}

auto parse_method(std::string_view from) -> std::pair<request_message::Method, std::size_t> {
    
    auto i = std::find_if(std::begin(METHOD_2_TYPE), std::end(METHOD_2_TYPE), [from] (auto&& val) {
        return val.first == from;
    });
    if (i == std::end(METHOD_2_TYPE)) {
        return {request_message::Method::ERROR, 0};
    }
    return {i->second, i->first.size()};
}

auto create_message_body(const std::string& from) -> std::string {
    auto bs = from.find(HTTP_HEADERS_END);
    if (bs != std::string::npos) {
        bs += HTTP_HEADERS_END.size();
        return from.substr(bs);
    }
    return {};
}

auto status_code = [](auto& start) -> bool {
    
    constexpr int MIN_VALID_STATUS = 100;
    constexpr int MAX_VALID_STATUS = 600;
    int status = 0;
	for (auto i = 0; i < DIGITS_STATUS_CODE && std::isdigit(*start); i++) {
		status = (status * 10) + (*start - '0');
	}
	return  status >= MIN_VALID_STATUS && status < MAX_VALID_STATUS;
};

auto match_response_line(std::string_view input) -> bool {
    // for example HTTPS/1.1 200 OK -> valid
    constexpr int MIN_SIZE_FOR_STRING_WITH_STATUS_CODE = DIGITS_STATUS_CODE + int(HTTP_DELIMITER.size());
	if (input.size() <= FIRST_WORD_RESPONSE.size()) {
		return false;
	}
	auto start = std::begin(input);
	for (auto fs = std::begin(FIRST_WORD_RESPONSE); fs != std::end(FIRST_WORD_RESPONSE); start++, fs++) {
		if (*fs != *start) {
			return false;
		}
	}
	if (*start == 'S') {
		++start;
	}
	if (*start != '/') {
		return false;
	}
	++start;
	if (*start != '1' && *start != '2') {
		return false;
	}
	++start;
	if (*start != '.') {
		return false;
	}
	++start;
	if (*start != '0' && *start != '1') {
		return false;
	}
	++start;
	if (!isspace(*start)) {
		return false;
	}
	++start;
	if (std::distance(start, std::end(input)) < MIN_SIZE_FOR_STRING_WITH_STATUS_CODE) {
		return false;
	}
	
	return status_code(start);
}

auto match_method(std::string_view::iterator start, std::string_view::iterator end, std::string_view method) -> std::string_view::iterator {
	// this is actually returns the iterator to the end of the method,
	// if the method is not found, returns end
	for (auto s = std::begin(method); start != end && s != std::end(method); ++s, ++start) {
		if (*s != *start) {
			return end;
		}
	}
	return start;
}

auto verify_method(std::string_view::iterator start, std::string_view::iterator end) -> std::pair<std::string_view::iterator, request_message::Method> {
    std::size_t index = std::size(METHODS) + 1;
	switch (*start) {
		case METHODS[0][0]:	// get
			start = match_method(start, end, METHODS[0]);
            index = 0;
            break;
		case METHODS[1][0]:	// delete
			start = match_method(start, end, METHODS[1]);
            index = 1;
            break;
		case METHODS[2][0]:	// connect
			start = match_method(start, end, METHODS[2]);
            index = 2;
            break;
		case METHODS[3][0]:	// head
			start = match_method(start, end, METHODS[3]);
            index = 3;
            break;
		case METHODS[4][0]:	// trace
			start =  match_method(start, end, METHODS[4]);
            index = 4;
            break;
		case METHODS[5][0]:	// option
			start =  match_method(start, end, METHODS[5]);
            index = 5;
            break;
		case METHODS[6][0]:	// patch or post or put
			switch (*(start + 1)) {
				case 'A':	// patch
					start =  match_method(start, end, METHODS[6]);
                    index = 6;
                    break;
				case 'O':
					start =  match_method(start, end, METHODS[7]);
                    index = 7;
                    break;
				case 'U':
					start =  match_method(start, end, METHODS[8]);
                    index = 8;
                    break;
				default:
					return {end, request_message::ERROR};
			}
            break;		
		default:
			return {end, request_message::ERROR};
	}
    if (start != end) {
        return {start, METHOD_2_TYPE[index].second};
    }
    return {end, request_message::ERROR};
}


auto match_request(std::string_view input) -> bool {
    // request line is the first line in the HTTP message by the client
    // GET /images/logo.png HTTP/1.1
    if (input.empty()) {
        return false;
    }
    auto [start, type] = verify_method(std::begin(input), std::end(input));
    if (start == std::end(input)) {
	    return false;
    }
    // we know that we have the string starts with none empty valid method name
    // now we must ensure that the first char after the first space is '/'
    // which is the path for the resource
    auto min_size = size_t(std::distance(std::begin(input), start)) + 2 + FIRST_WORD_RESPONSE.size() + HTTP_DELIMITER.size();
    if (input.size() < min_size) {
        return false;
    }
    
    // at this point we must have space than '/'
    if (!isspace(*start)) {
        return false;
    }
    ++start;
    if (type != request_message::CONNECT && *start != '/') {
        return false;
    }
    // now we need to skip the all path, this is after the next space we have
    auto e = input.find_first_of(HTTP_DELIMITER);
    if (e == std::string_view::npos) {
        return false;
    }
    auto ns = std::begin(input) + (e - 1);
    auto i = input.size();
    for (; ns != start && !std::isspace(*ns) && i > 0; --ns, --i) {
    }
    if (i == 0) {
        LOG_HTTP_PACKETS_FATAL << "we got to the point that we overlapped when searching for a space, this cannot be!!! (" << input.substr(0, std::min(512lu, input.size())) << ")";
    }
    if (ns == std::end(input)) {
        return false;
    }
    ++ns;
    for (auto s = std::begin(FIRST_WORD_RESPONSE); s != std::end(FIRST_WORD_RESPONSE); ++s, ++ns) {
        if (*s != *ns) {
            return false;
        }
    }
    return true;
}

struct http_tokenizer
{
    std::istringstream input;

    http_tokenizer(const std::string& data) : input{data} {
    }

    auto next() -> std::optional<std::string> {
        constexpr char LINE_END = '\n';
        constexpr char CR = '\r';
        if (input.eof() || input.bad()) {
            return {};      // we don't have input any more or error
        }
        std::string output;
        if (std::getline(input, output, LINE_END)) {
            if (output.back() == CR) {
                return output.substr(0, output.size() -1);
            }
        }
        return {};
    }
};

}   // end of local namespace

auto is_http_response_start(std::string_view payload) -> bool {
    return match_response_line(payload);
}

auto is_http_request_start(std::string_view payload) -> bool {
    return match_request(payload);
}


auto http_message_base::add_header(std::string hl) -> HeaderAdded {

    constexpr auto tokenized_header_line = [] (std::string&& header_line) -> header_t {
        
        auto e = header_line.find_first_of(HEADER_LIMITER);
        if (e == std::string::npos) {
            return {};
        }
        return {boost::algorithm::trim_copy(header_line.substr(0, e)), 
                boost::algorithm::trim_copy(header_line.substr(e + 1))
        };
    };

    if (hl.empty()) {
        return DONE_ADDING;
    }
    
    auto ne = tokenized_header_line(std::move(hl));
    if (ne.first.empty()) {
        return FAILED_ADDING;
    }
    headers.emplace_back(ne);
    return OK_ADDED;
}

http_message_base::http_message_base(std::string http_ver) {
    // this is in the form of HTTP[S]/<version number>
    auto t = tokenize_string(std::move(http_ver), "/");
    if (t.size() != 2) {    // error
        return;
    }
    if (boost::iequals(t[0], "HTTPS")) {
        is_encrypted = true;
    }
    if (t[1] == "1") {
        version = VERSION_1;
    } else if (t[1] == "1.1") {
        version = VERSION_1_1;
    } else if (t[1] == "2") {
        version = VERSION_2;
    } else {
        version = UNKOWN_VERSION;
    }
}

auto operator << (std::ostream& os, http_message_base::Version v) -> std::ostream& {
    switch (v) {
        case http_message_base::VERSION_1:
            return os << "1";
        case http_message_base::VERSION_1_1:
            return os << "1.1";
        case http_message_base::VERSION_2:
            return os << "2";
        case http_message_base::VERSION_3:
            return os << "3";
        default:
            return os << "unknown http version";
    }
}

auto operator << (std::ostream& os, const http_message_base& msg) -> std::ostream& {
    if (msg.headers.empty()) {
        return os << "invalid HTTP message";
    }
    os << (msg.is_encrypted ? "HTTPS" : "HTTP") << "/" << msg.version << "\nHeader: (" << msg.headers.size() << ")\n";
    for (const auto& h : msg.headers) {
        os << h.first << ": " << h.second << "\n";
    }
    return os << "with body of size " << msg.body.size();
}

request_message::request_message(std::string m, std::string url, std::string http_ver) : 
    http_message_base{std::move(http_ver)}, URL{url}, method{parse_method(m).first} {
}

auto operator << (std::ostream& os, request_message::Method m) -> std::ostream& {
    return os << to_string(m);
}

auto to_string(request_message::Method m) -> std::string {
    switch (m) {
        case request_message::Method::CONNECT:
            return  "CONNECT";
        case request_message::Method::DELETE:
            return  "DELETE";
        case request_message::Method::GET:
            return  "GET";
        case request_message::Method::HEAD:
            return  "HEAD";
        case request_message::Method::OPTIONS:
            return  "OPTIONS";
        case request_message::Method::PATCH:
            return  "PATCH";
        case request_message::Method::POST:
            return  "POST";
        case request_message::Method::PUT:
            return  "PUT";
        case request_message::Method::TRACE:
            return  "TRACE";
        case request_message::Method::ERROR:
        default:
            return  "ERROR";
    }
}

auto operator << (std::ostream& os, const request_message& msg) -> std::ostream& {
    if (msg.headers.empty()) {
        return os << "invalid HTTP request message";
    }
    os << "URL [" << msg.URL <<"] method: " << msg.method << ", ";
    return os << static_cast<const http_message_base&>(msg);
}


auto operator << (std::ostream& os, const response_message& msg) -> std::ostream& {
    if (msg.headers.empty()) {
        return os << "invalid HTTP response message";
    }
    os << "status code: " << msg.status_code << ", which is ";
    
    if (msg.server_error()) {
        os << "server error";
    }
    if (msg.client_error()) {
        os << "client error";
    }
    if (msg.success()) {
        os << "success";
    }
    if (msg.info()) {
        os << "info message";
    }
    if (msg.redirect()) {
        os << "redirect error";
    }
    return os << ", " << static_cast<const http_message_base&>(msg);
}

constexpr std::size_t MIN_MESSAGE_PRINT_LEN = 24;

auto response_message::try_from(const std::string& from) -> result<response_message, std::string> {
    constexpr std::size_t MIN_REQUEST_LINE_ENTRY = 3;
    static const std::size_t MIN_MESSAGE_SIZE = to_string(request_message::Method::GET).size() + 3 + FIRST_WORD_RESPONSE.size() + HTTP_DELIMITER.size();
    if (from.size() < MIN_MESSAGE_SIZE) {
        return failed("this is not a response: "s + from.substr(0, std::min(MIN_MESSAGE_PRINT_LEN, from.size())));
    }
    // get the first line from the input, this is the status line that has the basic info
    http_tokenizer tokenizer{from};
    if (auto rl = tokenizer.next(); rl) {
        auto status_line = rl.value();
        auto status_line_tokens = tokenize_string(std::move(status_line), " ");
        if (status_line_tokens.size() < MIN_REQUEST_LINE_ENTRY) {
            return failed("expecting to have "s + std::to_string(MIN_REQUEST_LINE_ENTRY) + " fields in the status line got "s + std::to_string(status_line_tokens.size()));
        }
        response_message response{std::move(status_line_tokens[1]), std::move(status_line_tokens[0])};
        auto l = tokenizer.next();
        auto max = MAX_HEADERS;
        while (l && max-- > 0) {
            auto r = response.add_header(std::move(l.value()));
            l = tokenizer.next();
            if (r == http_message_base::FAILED_ADDING) {
                return failed("got invalid header line"s);
            }
            if (r == http_message_base::DONE_ADDING) {
                response.body = std::move(create_message_body(from));;
                return ok(response);
            }
        }
    } else {
        return failed("failed to read anything from the input"s);
    }
    return failed("unknown error while trying to parse response message"s);
}

auto request_message::try_from(const std::string& from) -> result<request_message, std::string> {
   
    if (from.empty() || !is_http_request_start(from)) {
        return failed("this is not a request!: "s + (from.size() < MIN_MESSAGE_PRINT_LEN ? "empty or too small" : from.substr(0, MIN_MESSAGE_PRINT_LEN)));
    }
    // get the first line from the input, this is the request line that has the basic info
    http_tokenizer tokenizer{from};
    if (auto rl = tokenizer.next(); rl) {
        auto request_line = rl.value();
        if (request_line.empty()) {
            return failed("no request line was found in the message"s);
        }
        auto tok = tokenize_string(std::move(request_line), " ");
        if (tok.size() < MIN_STATUS_LINE_ENTRIES) {
            return failed("invalid length for request line expecting "s + std::to_string(MIN_STATUS_LINE_ENTRIES) + ", got "s  + std::to_string(tok.size()));
        }
        auto url = extract_url(tok);
        request_message request{tok[0], tok[1], tok[tok.size() - 1]};
        auto l = tokenizer.next();
        
        auto max = MAX_HEADERS;
        while (l && max-- > 0) {
            //std::cout << "header[" << c++ <<"]: <" <<l.value() << ">\n";
            auto r = request.add_header(std::move(l.value()));
            if (r == http_message_base::FAILED_ADDING) {
                return failed("invalid header line"s);
            }
            if (r == http_message_base::DONE_ADDING) {
                request.body = std::move(create_message_body(from));
                return ok(request);
            }
            l = tokenizer.next();
        }
    } else {
        return failed("failed to read anything from the input!!"s);
    }
    return failed("unknown error while parsing request"s);
}

}   // end of namespace parser
}   // end of namespace monitor