#include "capture_info.h"
#include "session.h"
#include "http_match.h"
#include "Log/logging.h"
#include <vector>
#include <gtest/gtest.h>


// The tests here are about making sure that we are 
// collecting the flows based on some values
// i.e. that we know how to save matching flows together
TEST(FlowMatchingTest, PortMatchingTest) {
    // in this test we have the same source and destination IPs
    // but different ports, we would like to ensure that we are 
    // collecting correctly here.
    using namespace monitor;
    using ports_t = std::tuple<TCP::port_type, TCP::port_type>;

    set_log_severity({{DEFAULT_HTTP_CHANNEL, severity_level::critical}});

    constexpr data_flow::timestamp_t RANDOM_TIME = 1683093070417;
    constexpr IPv4::address_type CLIENT_IP = 0x800000a;    // 10.0.0.8
    constexpr IPv4::address_type SERVER_IP= 0x94eddb3e;    // 62.219.237.148
    constexpr TCP::counter_type BASE_ACK = 0;
    constexpr TCP::counter_type BASE_SEQ_NUMBER = 1613975465;
    constexpr std::size_t NUMBER_OF_FLOWS = 10;

    const  ports_t ports[] = {  // random
        {1, 2}, {1, 3}, {1, 4}, {1, 5},
        {2, 27}, {3, 2}, {4, 2}, {5, 2}
    };

    data_flow base_flow {
        RANDOM_TIME, IPv4_flow{CLIENT_IP, SERVER_IP}, 
        TCP {
            0,  // we are going to override port
            0,  // we are going to override port
            BASE_ACK,                   // will change it
            BASE_SEQ_NUMBER,            // will change it
            false, true, false, false  // we will change this
        }
    };

    std::vector<data_flow> client_flows(std::size(ports), base_flow);
    std::vector<data_flow> server_flows(std::size(ports), base_flow);
    for (std::size_t i = 0; i < client_flows.size(); i++) {
        client_flows[i].tcp_layer.state.syn = true;
        client_flows[i].tcp_layer.state.ack = false;
        client_flows[i].tcp_layer.source_port = std::get<0>(ports[i]);
        client_flows[i].tcp_layer.dest_port = std::get<1>(ports[i]);
        server_flows[i].tcp_layer.source_port = std::get<1>(ports[i]);
        server_flows[i].tcp_layer.dest_port = std::get<0>(ports[i]);
        std::swap(server_flows[i].ipv4_layer.dest, server_flows[i].ipv4_layer.source);
        server_flows[i].tcp_layer.state.ack = true;
        server_flows[i].tcp_layer.state.syn = true;
    }
   
    sessions_repo repo;
    // we must start with client, as this is the initiator for the connection
    auto count = 0;
    for (auto f :  client_flows) {
        auto added = repo.add_flow(f);
        ASSERT_NE(added, repo.end()) << "failed to add flow # " << count << " for " << f;
        ASSERT_FALSE(added->second.done()) << "flow " << f << " is not the last one";
        ++count;
    }
    // then we can add in any order more flows
    ASSERT_EQ(repo.saved(), client_flows.size()) << "should have had " << client_flows.size() << ", but saved " << repo.saved();
    count = 0;
    for (auto f :  server_flows) {
        auto added = repo.add_flow(f);
        ASSERT_NE(added, repo.end()) << "failed to add flow # " << count << ": " << f;
        ASSERT_FALSE(added->second.done()) << "flow " << f << " is not the last one";
        count++;
    }
    ASSERT_EQ(repo.saved(), client_flows.size()) << "should have had " << client_flows.size() << ", but saved " << repo.saved();
    // add flows with data
    for (const auto& [k, s] : repo.sessions) {
        ASSERT_EQ(s.upstream_flows(), s.downstream_flows());   // same number up and down
        const auto verify = s.verify_flows();
        ASSERT_FALSE(verify.is_error()) << "we have invalid flow: " << verify;
    }

    // insert other flows, this time we need them to be without the syn and with data
    // adding data here should not increase the number of sessions, as all these flows
    // belong to existing sessions
    for (std::size_t i = 0; i < NUMBER_OF_FLOWS; i++) {
        auto client_start = client_flows.begin();
        for (auto server_start = server_flows.begin(); server_start != server_flows.end() && client_start != client_flows.end(); client_start++, server_start++) {
            server_start->app_data = data_flow::application_data(100 + i, '0');
            client_start->app_data = data_flow::application_data(100 + i, '0');
            client_start->tcp_layer.state.syn = false;
            client_start->tcp_layer.ack_num++;
            server_start->tcp_layer.ack_num++;
            client_start->tcp_layer.state.ack = true;
            server_start->tcp_layer.state.syn = false;
            auto added = repo.add_flow(*server_start);
            ASSERT_NE(repo.end(), added);
            ASSERT_EQ(repo.saved(), client_flows.size());
            ASSERT_FALSE(added->second.done());
            added = repo.add_flow(*client_start);
            ASSERT_NE(repo.end(), added);
            ASSERT_EQ(repo.saved(), client_flows.size());
            ASSERT_FALSE(added->second.done());
        }
    }

    // make sure that we have for each session the same port and IP pairs
    count = 0;
    for (const auto& [k, f] : repo.sessions) {
        ASSERT_EQ(f.upstream_flows(), f.downstream_flows()) << "at " << count << " the number of flows for upstream " 
            << f.upstream_flows() << " !=  downstream " << f.downstream_flows();   // same number up and down
        ASSERT_EQ(f.upstream_flows(), NUMBER_OF_FLOWS + 1) << "we have " << f.upstream_flows() << " flows for session number " << count;
        const auto verify = f.verify_flows();
        ASSERT_FALSE(verify.is_error()) << "at " << count << ", we have invalid flow: " << verify;
        count++;
    }
}

TEST(FlowMatchingTest, AddressesMatchingTest) {
    // in this test we have the same source and destination ports
    // but different source/destination addresses, we would like to ensure that we are 
    // collecting correctly here.
    using namespace monitor;
    using addresses_t = std::tuple<IPv4::address_type, IPv4::address_type>;

    set_log_severity({{DEFAULT_HTTP_CHANNEL, severity_level::critical}});

    constexpr data_flow::timestamp_t RANDOM_TIME = 1683093070417;
    IPv4::address_type CLIENT_IP = 0x800000a;    // 10.0.0.8
    IPv4::address_type SERVER_IP= 0x94eddb3e;    // 62.219.237.148
    constexpr TCP::port_type CLIENT_PORT = 12345;
    constexpr TCP::port_type SERVER_PORT = 5432;
    constexpr TCP::counter_type BASE_ACK = 0;
    constexpr TCP::counter_type BASE_SEQ_NUMBER = 1613975465;
    constexpr std::size_t NUMBER_OF_FLOWS = 10;

    const  addresses_t addresses[] = {  // random
        {CLIENT_IP, SERVER_IP}, {CLIENT_IP + 1, SERVER_IP + 1}, {CLIENT_IP + 2, SERVER_IP + 2}, {CLIENT_IP + 3, SERVER_IP + 3},
        {CLIENT_IP + 4, SERVER_IP + 4}, {CLIENT_IP + 5, SERVER_IP}, {CLIENT_IP + 6, SERVER_IP}, {CLIENT_IP + 7, SERVER_IP}
    };

    data_flow base_flow {
        RANDOM_TIME, IPv4_flow{CLIENT_IP, SERVER_IP}, 
        TCP {
            CLIENT_PORT,    // we are going to override port
            SERVER_PORT,      // we are going to override port
            BASE_ACK,                   // will change it
            BASE_SEQ_NUMBER,            // will change it
            false, true, false, false  // we will change this
        }
    };

    std::vector<data_flow> client_flows(std::size(addresses), base_flow);
    std::vector<data_flow> server_flows(std::size(addresses), base_flow);
    for (std::size_t i = 0; i < client_flows.size(); i++) {
        client_flows[i].tcp_layer.state.syn = true;
        client_flows[i].tcp_layer.state.ack = false;
        client_flows[i].ipv4_layer.source.address = std::get<0>(addresses[i]);
        client_flows[i].ipv4_layer.dest.address = std::get<1>(addresses[i]);
        server_flows[i].ipv4_layer.source.address = std::get<1>(addresses[i]);
        server_flows[i].ipv4_layer.dest.address = std::get<0>(addresses[i]);
        std::swap(server_flows[i].tcp_layer.source_port, server_flows[i].tcp_layer.dest_port);
        server_flows[i].tcp_layer.state.syn = true;
    }
    sessions_repo repo;
    // client flows must come first as this initiate the connection
    for (auto f :  client_flows) {
        auto added = repo.add_flow(f);
        ASSERT_NE(added, repo.end()) << "failed to add flow " << f;
        ASSERT_FALSE(added->second.done()) << "flow " << f << " is not the last one";
    }
    ASSERT_EQ(repo.saved(), client_flows.size()) << "should have had " << client_flows.size() << ", but saved " << repo.saved();
    // then we can add more flows
    for (auto f :  server_flows) {
        auto added = repo.add_flow(f);
        ASSERT_NE(added, repo.end()) << "failed to add flow " << f;
        ASSERT_FALSE(added->second.done()) << "flow " << f << " is not the last one";
    }
    ASSERT_EQ(repo.saved(), client_flows.size()) << "should have had " << client_flows.size() << ", but saved " << repo.saved();

    for (const auto& [k, s] : repo.sessions) {
        ASSERT_EQ(s.upstream_flows(), s.downstream_flows());   // same number up and down
        const auto verify = s.verify_flows();
        ASSERT_FALSE(verify.is_error()) << "we have invalid flow: " << verify;
    }

    // insert other flows, this time we need them to be without the syn and with data
    // adding data here should not increase the number of sessions, as all these flows
    // belong to existing sessions
    for (std::size_t i = 0; i < NUMBER_OF_FLOWS; i++) {
        auto client_start = client_flows.begin();
        for (auto server_start = server_flows.begin(); server_start != server_flows.end() && client_start != client_flows.end(); client_start++, server_start++) {
            server_start->app_data = data_flow::application_data(100, '0');
            client_start->app_data = data_flow::application_data(100, '0');
            client_start->tcp_layer.state.syn = false;
            client_start->tcp_layer.state.ack = true;
            server_start->tcp_layer.state.syn = false;
            auto added = repo.add_flow(*server_start);
            ASSERT_NE(repo.end(), added);
            ASSERT_EQ(repo.saved(), client_flows.size());
            ASSERT_FALSE(added->second.done());
            added = repo.add_flow(*client_start);
            ASSERT_NE(repo.end(), added);
            ASSERT_EQ(repo.saved(), client_flows.size());
            ASSERT_FALSE(added->second.done());
        }
    }

    // make sure that we have for each session the same port and IP pairs
    for (const auto& [k, f] : repo.sessions) {
        ASSERT_EQ(f.upstream_flows(), f.downstream_flows());   // same number up and down
        ASSERT_EQ(f.upstream_flows(), NUMBER_OF_FLOWS + 1);
        const auto verify = f.verify_flows();
        ASSERT_FALSE(verify.is_error()) << "we have invalid flow: " << verify;
    }
}

TEST(FlowMatchingTest, TestHttpResponseMatching) {
    constexpr std::string_view pattens[] = {
        "HTTP/1.1 400 Bad Request\r\n",
        "HTTP/1.1 503 Backend fetch failed\r\n", "HTTPS/2.0 123 foo bar\r\nthis is the reset of it",
        "HTTPS/1.0 343\r\n", "HTTP/1.1 443 this is yet another reason\r\nheader: 1\r\nthis:this is header",
        "HTTP/1.1 555 we have a good reason to test this\r\n"
    };
    for (auto&& p : pattens) {
        EXPECT_TRUE(monitor::parser::is_http_response_start(p)) << "we are expecting that pattern " << std::quoted(p) << " will be matched as valid HTTP response status line";
    }
}

TEST(FlowMatchingTest, TestHttpResponseNotMatching) {
    constexpr std::string_view pattens[] = {
        "HTTP/1.2 503 Backend fetch failed", "HTTPS/2.0 623 foo bar\r\nthis is the reset of it",
        "HTTPS/1.0", "HTTPY/1.1 443 this is yet another reason\r\nheader: 1\r\nthis:this is header",
        "HTTP/0.1 555 we have a good reason to test this" "   HTTP/1.1 555 we have a good",
        "OPTIONS /usernamepassword/challenge HTTP/1.0\r\n",
        "GET /path/script.cgi?field1=value1&field2=value2 HTTP/1.1\r\n",
        "POST /i?a=apphub/logrocket&r=5-58d40ced-3b20-44b7-a3e3-604eb778b003&t=b88a990c-fd27-44e5-9685-9b72d113e220&s=2&des=false&rs=2,t&u=431e57c4-6611-4b22-bf68-c02914af9936&is=1 HTTP/1.1\r\n",
        "HTTPS/1.0 343"
    };
    for (auto&& p : pattens) {
        EXPECT_FALSE(monitor::parser::is_http_response_start(p)) << "we are expecting that pattern " << std::quoted(p) << " will be not be matched as valid HTTP response status line";
    }
}

TEST(FlowMatchingTest, MatchHttpRequestLine) {
    constexpr std::string_view pattens[] = {
        "GET /hello%3Ca%20target=%22x%22%20href=%22xssme?xss=<script>find('cookie'); var doc = getSelection().getRangeAt(0).startContainer.ownerDocument; console.log(doc); var xpe = new XPathEvaluator(); var nsResolver = xpe.createNSResolver(doc); var result = xpe.evaluate('//script/text()', doc, nsResolver, 0, null); confirm(result.iterateNext().data.match(/cookie = '(.*?)'/)[1])</script> HTTP/1.1\r\n",
        "GET /hello%3C? echo('<scr)'; echo('ipt>confirm(\"XSS\")</script>'); ?> HTTP/1.1\r\n",
        "GET /path/script.cgi?field1=value1&field2=value2 HTTP/1.1\r\n",
        "GET /index.html HTTP/1.1\r\n", 
        "GET /tienda1/imagenes/3.gif/ HTTP/1.1\r\n",
        "POST /i?a=apphub/logrocket&r=5-58d40ced-3b20-44b7-a3e3-604eb778b003&t=b88a990c-fd27-44e5-9685-9b72d113e220&s=2&des=false&rs=2,t&u=431e57c4-6611-4b22-bf68-c02914af9936&is=1 HTTP/1.1\r\n",
        "OPTIONS /usernamepassword/challenge HTTP/1.0\r\n", 
        "POST /eligible.json?account_token=NPS-a22e04b1&end_user_last_seen=1695833061188&language[code]=&language[audience_text]=&language[product_name]=&sdk_version=wootric-js-sdk-1.11.2&segment_user_id=151604dd-086f-4c87-9a7a-183f1ecdc56e HTTPS/1.1\r\n",
        "CONNECT www.example.re:80 HTTP/1.1\r\n"
    };

    for (auto&& p : pattens) {
        EXPECT_TRUE(monitor::parser::is_http_request_start(p)) << "we are expecting that pattern " << std::quoted(p) << " will be matched as valid HTTP request";
    }
}

TEST(FlowMatchingTest, DontMatchHttpRequestLine) {
    constexpr std::string_view pattens[] = {
        "GGET /path/script.cgi?field1=value1&field2=value2 HTTP/1.1\r\n",
        "GET index.html HTTP/1.1\r\n", 
        "GET /tienda1/imagenes/3.gif/ HHTTP/1.1\r\n",
        "POST /i?a=apphub/logrocket&r=5-58d40ced-3b20-44b7-a3e3-604eb778b003&t=b88a990c-fd27-44e5-9685-9b72d113e220&s=2&des=false&rs=2,t&u=431e57c4-6611-4b22-bf68-c02914af9936&is=1HTTP/1.1\r\n",
        "OPTIONS /", 
        "POST t/eligible.json?account_token=NPS-a22e04b1&end_user_last_seen=1695833061188&language[code]=&language[audience_text]=&language[product_name]=&sdk_version=wootric-js-sdk-1.11.2&segment_user_id=151604dd-086f-4c87-9a7a-183f1ecdc56e HTTPS/1.1\r\n",
        "HTTP/1.1 503 Backend fetch failed\r\n", "HTTPS/2.0 123 foo bar\r\nthis is the reset of it",
        "HTTPS/1.0 343\r\n", "HTTP/1.1 443 this is yet another reason\r\nheader: 1\r\nthis:this is header",
        "HTTP/1.1 555 we have a good reason to test this\r\n",
        "CONNECT HTTTP/1.1"
    };

    for (auto&& p : pattens) {
        EXPECT_FALSE(monitor::parser::is_http_request_start(p)) << "we are expecting that pattern " << std::quoted(p) << " will NOT be matched as valid HTTP request";
    }
}