// Test that we can parse messages into HTTP
#include <gtest/gtest.h>
#include "capture_info.h"
#include "formatter.h"
#include "Log/logging.h"


namespace
{
    constexpr std::uint16_t CLIENT_PORT = 12345;
    constexpr std::uint16_t SERVER_PORT = 123;
    constexpr monitor::IPv4::address_type CLIENT_IP = 0x800000a;    // 10.0.0.8
    constexpr monitor::IPv4::address_type SERVER_IP= 0x94eddb3e;    // 62.219.237.148
    constexpr monitor::data_flow::timestamp_t BASIC_TIMESTAMP = 1683093070417;  // just random date
    constexpr monitor::TCP::counter_type BASE_ACK = 0;
    constexpr monitor::TCP::counter_type BASE_SEQ_NUMBER = 1613975465;
    constexpr monitor::TCP::counter_type BASE_SERVER_SEQ_NUM = 2846102662;
    const std::uint8_t* HTTP_GET = (const std::uint8_t*)"GET / HTTP/1.1\r\nHost: www.ag-n.co.il\r\n\r\nUser-Agent: curl/7.81.0\r\nAccept: */*\r\n";
    const std::uint8_t* HTTP_RESPONSE_BODY = (const std::uint8_t*)"l 0.2s ease-out;-ms-transition:all 0.2s ease-out}.tp-caption a:hover{color:#ffa902}.tp-caption a{color:"
        "#ff7302;text-shadow:none;-webkit-transition:all 0.2s ease-out;-moz-transition:all 0.2s ease-out;-o-transition:all 0.2s ease-out;-ms-transition:all 0.2s ease-out}"
        ".tp-caption a:hover{color:#ffa902}.tp-caption a{color:#ff7302;text-shadow:none;-webkit-transition:all 0.2s ease-out;-moz-transition:all 0.2s ease-out;-o-transition:all 0.2s ease-out;"
        "-ms-transition:all 0.2s ease-out}.tp-caption a:hover{color:#ffa902}.tp-caption a{color:#ff7302;text-shadow:none;-webkit-transition:all 0.2s ease-out;-moz-transition:all 0.2s "
        "ease-out;-o-transition:all 0.2s ease-out;-ms-transition:all 0.2s ease-out}.tp-caption a:hover{color:#ffa902}.tp-caption a{color:#ff7302;text-shadow:none;-webkit-transition:all 0.2s"
        " ease-out;-moz-transition:all 0.2s ease-out;-o-transition:all 0.2s ease-out;-ms-transition:all 0.2s ease-out}.tp-caption a:hover{color:#ffa902}.tp-caption a{color:#ff7302;"
        "text-shadow:none;-webkit-transition:all 0.2s ease-out;-moz-transition:all 0.2s ease-out;-o-transition:all 0.2s ease-out;-ms-transition:all 0.2s ease-out}.tp-caption"
        " a:hover{color:#ffa902}.tp-caption a{color:#ff7302;text-shadow:none;-webkit-transition:all 0.2s ease-out;-moz-transition:all 0.2s ease-out;-o-transition:all 0.2s"
        " ease-out;-ms-transition:all 0.2s ease-out}.tp-caption a:hover{color:#ffa902}.tp-caption a{color:#ff7302;text-shadow:none;-webkit-transition:all 0.2s ease-out;"
        "-moz-transition:all 0.2s ease-out;-o-transition:all 0.2s ease-out;-ms-transition:all 0.2s ease-out}.tp-caption a:hover{color:#ffa902}.tp-caption a{color:#ff7302;"
        "text-shadow:none;-webkit-transition:all 0.2s ease-out;-moz-transition:all 0.2s ease-out;-o-transition:all 0.2s ease-out;-ms-transition:all 0.2s ease-out}"
        ".tp-caption a:hover{color:#ffa902}.tp-caption a{color:#ff7302;text-shadow:none;-webkit-transition:all 0.2s ease-out;-moz-transition:all 0.2s ease-out;-o-transition:"
        "all 0.2s ease-out;-ms-transition:all 0.2s ease-out}.tp-caption a:hover{color:#ffa902}.tp-caption a{color:#ff7302;text-shadow:none;-webkit-transition:all 0.2s ease-out;"
        "-moz-transition:all 0.2s ease-out;-o-transition:all 0.2s ease-out;-ms-transition:all 0.2s ease-out}.tp-caption a:hover{color:#ffa902}.tp-caption a{color:#ff7302;text-shadow:none;"
        "-webkit-transition:all 0.2s ease-out;-moz-transition:all 0.2s ease-out;-o-transition:all 0.2s ease-out;-ms-transition:all 0.2s ease-out}.tp-caption a:hover{color:#ffa902}.tp-caption"
        " a{color:#ff7302;text-shadow:none;-webkit-transition:all 0.2s ease-out;-moz-transition:all 0.2s ease-out;-o-transition:all 0.2s ease-out;-ms-transition:all 0.2s ease-out}.tp-caption a:"
        "hover{color:#ffa902}.tp-caption a{color:#ff7302;text-shadow:none;-webkit-transition:all 0.2s ease-out;-moz-transition:all 0.2s ease-out;-o-transition:all 0.2s ease-out;-ms-transit";
    const std::uint8_t* HTTP_RESPONSE_HTTP_HEADER_PARTIAL_BODY = (const std::uint8_t*)"HTTP/1.1 200 OK\r\n"
        "Connection: Keep-Alive\r\n"
        "Keep-Alive: timeout=5, max=100\r\n"
        "x-powered-by: PHP/5.6.40\r\n"
        "content-type: text/html; charset=utf-8\r\n"
        "expires: Wed, 17 Aug 2005 00:00:00 GMT\r\n"
        "last-modified: Sun, 30 Apr 2023 09:03:20 GMT\r\n"
        "cache-control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0\r\n"
        "pragma: no-cache\r\n"
        "content-length: 93560\r\n"
        "date: Sun, 30 Apr 2023 09:17:45 GMT\r\n"
        "server: LiteSpeed\r\n"
        "vary: User-Agent\r\n"
        "Set-Cookie: cookiesession1=678B286F8DA254AB87A9D3BE8E62CCA5;Expires=Mon, 29 Apr 2024 09:17:46 GMT;Path=/;HttpOnly\r\n"
        "\r\n"
        "<!DOCTYPE html>\n"
        "<!--[if lt IE 7]>\n"
        "<html class=\"no-js lt-ie9 lt-ie8 lt-ie7\" dir=\"rtl\" lang=\"he-IL\" prefix=\"og: http://ogp.me/ns#\"> <![endif]-->\n"
        "<!--[if IE 7]>\n"
        "<html class=\"no-js lt-ie9 lt-ie8\" dir=\"rtl\" lang=\"he-IL\" prefix=\"og: http://ogp.me/ns#\"> <![endif]-->\n"
        "<!--[if IE 8]>"
        "<html class=\"no-js lt-ie9\" dir=\"rtl\" lang=\"he-IL\" prefix=\"og: http://ogp.me/ns#\"> <![endif]-->"
        "<!--[if gt IE 8]><!--> <html class=\"no-js\" dir=\"rtl\" lang=\"he-IL\" prefix=\"og: http://ogp.me/ns#\"> <!--<![endif]-->"
        "<head>\n"
        "   <meta charset=\"utf-8\" />\n"
        "   <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n"
        "   <title>××£ ××××ª - × ××¨×¨×× - ×××¦××¨ ××ª××§×× × ××¨×¨××</title>\n"
        "\n"
        "<!-- This site is optimized with the Yoast SEO plugin v4.5 - https://yoast.com/wordpress/plugins/seo/ -->"
        "<link rel=\"canonical\" href=\"http://www.ag-n.co.il/\" />"
        "<meta property=\"og:locale\" content=\"he_IL\" />"
        "<meta property=\"og:type\" content=\"website\" />"
        "<meta property=\"og:title\" content=\"××£ ××××ª - × ××¨×¨×× - ×××¦××¨ ××ª××§××\";";

    // TCP connect message, note that this is form the client to the server
    // and we don't have data yet
    const monitor::data_flow tcp_client_connect {
        BASIC_TIMESTAMP, 
        monitor::IPv4_flow {
            CLIENT_IP,
            SERVER_IP
        },
        monitor::TCP {
            CLIENT_PORT,
            SERVER_PORT,
            BASE_ACK,
            BASE_SEQ_NUMBER,
            false,  // no finish flag
            false,  // no ack flag
            true,   // with syn flag
            false   // no reset
        }
    };

    // server reply to the TCP connect message
    const monitor::data_flow tcp_server_accept {
        BASIC_TIMESTAMP + 1, 
        monitor::IPv4_flow {
            SERVER_IP,
            CLIENT_IP
        },
        monitor::TCP {
            SERVER_PORT,
            CLIENT_PORT,
            BASE_SEQ_NUMBER + 1,    // server ack
            BASE_SERVER_SEQ_NUM,    // server seq
            false,  // no finish flag
            true,  // with ack flag
            true,   // with syn flag
            false   // no reset
        }
    };

    // client reply with ack
    const monitor::data_flow client_ack_accept {
        BASIC_TIMESTAMP + 2, 
        monitor::IPv4_flow {
            CLIENT_IP,
            SERVER_IP
        },
        monitor::TCP {
            CLIENT_PORT,
            SERVER_PORT,
            BASE_SERVER_SEQ_NUM + 1,    // ack
            BASE_SEQ_NUMBER + 1,        // seq
            false,  // no finish flag
            true,  // with ack flag
            false,   // no syn flag
            false   // no reset
        }
    };

    // client HTTP GET message
    const monitor::data_flow client_http_get {
        BASIC_TIMESTAMP + 3, 
        monitor::IPv4_flow {
            CLIENT_IP,
            SERVER_IP
        },
        monitor::TCP {
            CLIENT_PORT,
            SERVER_PORT,
            BASE_SERVER_SEQ_NUM + 1,    // ack
            BASE_SEQ_NUMBER + 1,        // seq
            false,  // no finish flag
            true,  // with ack flag
            false,   // no syn flag
            false   // no reset
        },
        monitor::data_flow::application_data{HTTP_GET}
    };

    // server sends reply to client - out of order at the HTTP level
    const monitor::data_flow server_out_of_order_http_response {
        BASIC_TIMESTAMP + 4,
        monitor::IPv4_flow {
            SERVER_IP,
            CLIENT_IP
        },
        monitor::TCP {
            SERVER_PORT,
            CLIENT_PORT,
            BASE_SEQ_NUMBER + 79,         // server ack
            BASE_SERVER_SEQ_NUM + 10022,  // server seq
            false,      // no finish flag
            true,       // with ack flag
            false,      // no syn flag
            false       // no reset
        },
        monitor::data_flow::application_data{HTTP_RESPONSE_BODY}
    };

    // then we have the reply with the HTTP headers from the server
    const monitor::data_flow server_http_response_headers {
        BASIC_TIMESTAMP + 4,
        monitor::IPv4_flow {
            SERVER_IP,
            CLIENT_IP
        },
        monitor::TCP {
            SERVER_PORT,
            CLIENT_PORT,
            BASE_SEQ_NUMBER + 79,     // server ack
            BASE_SERVER_SEQ_NUM + 1,  // server seq
            false,  // no finish flag
            true,  // with ack flag
            false,   // no syn flag
            false   // no reset
        },
        monitor::data_flow::application_data{HTTP_RESPONSE_HTTP_HEADER_PARTIAL_BODY}
    };

    const monitor::data_flow tcp_client_close {
        BASIC_TIMESTAMP + 5, 
        monitor::IPv4_flow {
            CLIENT_IP,
            SERVER_IP
        },
        monitor::TCP {
            CLIENT_PORT,
            SERVER_PORT,
            94097,                      // ack - skipping messages in this tests
            BASE_SEQ_NUMBER + 79,        // seq
            true,  // no finish flag
            true,  // with ack flag
            false,   // no syn flag
            false   // no reset
        }
    };

    const monitor::data_flow server_close_connection {
        BASIC_TIMESTAMP + 4,
        monitor::IPv4_flow {
            SERVER_IP,
            CLIENT_IP
        },
        monitor::TCP {
            SERVER_PORT,
            CLIENT_PORT,
            BASE_SEQ_NUMBER + 80,         // server ack
            BASE_SERVER_SEQ_NUM + 94097,  // server seq - skipping here on messages
            true,  // no finish flag
            true,  // with ack flag
            false,   // with syn flag
            false   // no reset
        }
    };
}   // end of local namespace

TEST(HttpPacketFormatter, TestRebuildFlow) {
    set_log_severity({{DEFAULT_HTTP_CHANNEL, severity_level::critical}});
    // build the sequence of the messages
    monitor::data_flow flows[] = {
        tcp_client_connect,
        tcp_server_accept,
        client_ack_accept,
        client_http_get,
        server_out_of_order_http_response,
        server_http_response_headers,
        tcp_client_close
    };
    monitor::sessions_repo repo;
    for (auto flow : flows) {
        auto res = repo.add_flow(flow);
        if (res == repo.end()) {
            ASSERT_TRUE(flow.control_only()) << "we are expecting this to be control flow: " << flow;
        } else {
            ASSERT_FALSE(flow.control_only()) << "we are expecting that this flow is not control only " << flow;
        }
        ASSERT_EQ(repo.saved(), 1);
        ASSERT_FALSE(repo.begin()->second.done()); // we don't have the end in this sequence yet
    }
    auto res = repo.add_flow(server_close_connection);
    ASSERT_NE(res, repo.end());
    ASSERT_EQ(repo.saved(), 1);
    ASSERT_TRUE(repo.begin()->second.done());
    ASSERT_EQ(repo.begin()->second.downstream_flows(), 4);
    ASSERT_EQ(repo.begin()->second.upstream_flows(), 3);
}

TEST(HttpPacketFormatter, FormatMessage) {
    set_log_severity({{DEFAULT_HTTP_CHANNEL, severity_level::critical}});
    monitor::data_flow flows[] = {
        tcp_client_connect,
        tcp_server_accept,
        client_ack_accept,
        client_http_get,
        server_out_of_order_http_response,
        server_http_response_headers,
        tcp_client_close,
        server_close_connection
    };
    monitor::sessions_repo repo;
    for (auto flow : flows) {
        auto res = repo.add_flow(flow);
        if (res == repo.end()) {
            ASSERT_TRUE(flow.control_only());
        } else {
            ASSERT_FALSE(flow.control_only());
        }
        ASSERT_EQ(repo.saved(), 1);
    }
    ASSERT_EQ(repo.saved(), 1);
    ASSERT_TRUE(repo.begin()->second.done());

    auto format_result = monitor::output_formatter::transform(repo.begin()->second.take());
    // this should succeed since we have a valid HTTP message inside here
    ASSERT_FALSE(format_result.is_error()) << "failed to format: " << format_result;
}

TEST(HttpPacketFormatter, InvalidRequestMessage) {
    set_log_severity({{DEFAULT_HTTP_CHANNEL, severity_level::critical}});

    monitor::data_flow flows[] = {
        tcp_client_connect,
        tcp_server_accept,
        client_ack_accept,
        server_out_of_order_http_response,
        server_http_response_headers,
        tcp_client_close,
        server_close_connection
    };
    monitor::sessions_repo repo;
    for (auto flow : flows) {
        auto res = repo.add_flow(flow);
        if (res == repo.end()) {
            ASSERT_TRUE(flow.control_only());
        } else {
            ASSERT_FALSE(flow.control_only());
        }
        ASSERT_EQ(repo.saved(), 1);
    }
    ASSERT_EQ(repo.saved(), 1);
    ASSERT_TRUE(repo.begin()->second.done());

    auto format_result = monitor::output_formatter::transform(repo.begin()->second.take());
    // This should fail since we don't have the request at all
    ASSERT_TRUE(format_result.is_error()) << "we should have error here, but for some reason formatting was successful";
}

TEST(HttpPacketFormatter, InvalidResponseMessage) {
    set_log_severity({{DEFAULT_HTTP_CHANNEL, severity_level::critical}});

    monitor::data_flow flows[] = {
        tcp_client_connect,
        tcp_server_accept,
        client_ack_accept,
        client_http_get,
        server_out_of_order_http_response,
        tcp_client_close,
        server_close_connection
    };
    monitor::sessions_repo repo;
    for (auto flow : flows) {
        auto res = repo.add_flow(flow);
        if (res == repo.end()) {
            ASSERT_TRUE(flow.control_only());
        } else {
            ASSERT_FALSE(flow.control_only());
        }
        ASSERT_EQ(repo.saved(), 1);
    }
    ASSERT_EQ(repo.saved(), 1);
    ASSERT_TRUE(repo.begin()->second.done());

    auto format_result = monitor::output_formatter::transform(repo.begin()->second.take());
    // This should fail since we don't have the response headers
    ASSERT_TRUE(format_result.is_error()) << "we should have error here, but for some reason formatting was successful";
}
