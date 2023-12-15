#include "capture.h"
#include "capture_info.h"
#include "channel.h"
#include "test_ut/http_packet_capture_ut_data.h"
#include "Log/logging.h"
#include <pcap.h>
#include <gtest/gtest.h>
#include <numeric>

namespace
{
    auto packet_memory(tests::packet_data_t msg) -> std::size_t {
        auto header = tests::make_pcap_header(std::uint32_t(msg.size()));
        auto pr = monitor::from_capture(&header, msg.data(), monitor::ethernet_header_len());
        if (pr) {
            return pr.value().app_data.size();
        }
        return 0;
    }
    // to calculate the size of the payloads we actually need to parse them and from this to generate the size
    // this function will tell us
    auto calculate_payload_size() -> std::size_t {
        const tests::packet_data_t all_messages[] = {
            tests::client_ack_packet(), tests::client_connect_packet(), tests::client_http_get_packet(),
            tests::client_tcp_close_packet(), tests::server_accept_packet(), tests::server_ack_packet(),
            tests::server_http_response_http_body(), tests::server_tcp_close_packet()
        };
        return std::accumulate(std::begin(all_messages), std::end(all_messages), 0lu, [](std::size_t cur, tests::packet_data_t msg) {            
            return cur + packet_memory(msg);
        });
    }
}   // end of local namespace

// This test will verity that we apply correctly the
// rate limit on memory
// Note that we have 2 types:
// 1. Overall memory usage, this means that we don't let the application to use more memory than we have configured
// 2. Per session memory usage, so that we don't let one message consume all the memory.
TEST(TestMemoryLimits, TestPerMessageMemory) {
    // create some flows and ensure that while one is blocked because of the size, other are not.
    using namespace monitor;

    set_log_severity({{DEFAULT_HTTP_CHANNEL, severity_level::critical}});

    using ports_t = std::tuple<TCP::port_type, TCP::port_type>;

    constexpr data_flow::timestamp_t RANDOM_TIME = 1683093070417;
    constexpr IPv4::address_type CLIENT_IP = 0x900000a;    // 10.0.0.9
    constexpr IPv4::address_type SERVER_IP= 0x95eddb3f;    // 63.219.237.149
    constexpr TCP::counter_type BASE_ACK = 0;
    constexpr TCP::counter_type BASE_SEQ_NUMBER = 161397588;
    constexpr std::uint64_t MAX_SIZE_FOR_MESSAGE = 100; // the overall size for a single message in bytes
    constexpr std::uint64_t DELTA_FROM_MAX_SIZE = 10;

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

    const  ports_t ports[] = {  // random
        {1, 2}, {1, 3}, {1, 4}, {1, 5},
        {2, 27}, {3, 2}, {4, 2}, {5, 2}
    };
    // for this test client is good enough
    std::vector<data_flow> client_flows(std::size(ports), base_flow);
    for (std::size_t i = 0; i < client_flows.size(); i++) {
        client_flows[i].tcp_layer.state.syn = true;
        client_flows[i].tcp_layer.state.ack = false;
        client_flows[i].tcp_layer.source_port = std::get<0>(ports[i]);
        client_flows[i].tcp_layer.dest_port = std::get<1>(ports[i]);
    }
    
    sessions_repo repo;
    repo.set_rate_limit(MAX_SIZE_FOR_MESSAGE);
    // set initial flows - no data in them
    for (auto f :  client_flows) {
        auto added = repo.add_flow(f);
        ASSERT_NE(added, repo.end()) << "failed to add flow " << f;
        ASSERT_FALSE(added->second.done()) << "flow " << f << " is not the last one";
    }
    ASSERT_EQ(repo.saved(), client_flows.size()) << "should have had " << client_flows.size() << ", but saved " << repo.saved();
    
    // so far so good, now lets populate with data, note that we will put
    // just enough so we will not block in this loop
    for (auto& f :  client_flows) {
        f.tcp_layer.state.syn = false;
        f.tcp_layer.state.ack = true;
        f.app_data = data_flow::application_data(MAX_SIZE_FOR_MESSAGE - DELTA_FROM_MAX_SIZE, '0');  // so we are 10 short to be blocked
        auto added = repo.add_flow(f);
        ASSERT_NE(added, repo.end()) << "failed to add flow " << f;
        ASSERT_FALSE(added->second.done()) << "flow " << f << " is not the last one";
        ASSERT_EQ(added->second.upstream_flows(), 2);
        ASSERT_TRUE(added->second.downstream_flows()  == 0);
    }

    std::vector<std::uint64_t> ids;
    std::transform(repo.begin(), repo.end(), std::back_inserter(ids), [] (const auto e) {
        return e.first;
    });
    
    const auto session_to_overflow_memory = ids.at(ids.size() / 3);   // just random location
    auto session_to_overflow = repo.sessions[session_to_overflow_memory].first_upstream();
    session_to_overflow.app_data = data_flow::application_data(DELTA_FROM_MAX_SIZE - 1, 't');
    // now we have one flow that is just one byte less than what we are allowing
    auto added_in_overflow = repo.add_flow(session_to_overflow);
    ASSERT_NE(added_in_overflow, repo.end()) << "failed to add flow " << session_to_overflow;
    ASSERT_FALSE(added_in_overflow->second.done()) << "flow " << session_to_overflow << " is not the last one";
    ASSERT_EQ(added_in_overflow->second.upstream_flows(), 3);
    ASSERT_TRUE(added_in_overflow->second.downstream_flows()  == 0);
    // now add more data to all, we will make sure that in the one entry that are now almost overflow,
    // the overflow will happen
    std::vector<std::size_t> current_sizes(repo.saved(), 0);
    std::transform(std::begin(repo), std::end(repo), std::begin(current_sizes), [] (const auto& s) {
        return s.second.upstream_flows();
    });
    std::size_t i = 0;
    
    for (auto& f :  client_flows) {
        const auto id = monitor::make_id(f);
        f.app_data = data_flow::application_data(DELTA_FROM_MAX_SIZE, '1');  // so we are 10 short to be blocked
        auto added = repo.add_flow(f);
        if (id == session_to_overflow_memory) {
            ASSERT_EQ(added, repo.end()) << "we are expecting that for " << session_to_overflow_memory << ", which should over flow, add " << f << ", will fail";
        } else {
            ASSERT_NE(added, repo.end()) << "at " << id << ", failed to add flow " << f << ", we are using size of " << f.payload_size() << " bytes for this flow out of " << MAX_SIZE_FOR_MESSAGE;
            // for all the others it will
            ASSERT_EQ(added->second.upstream_flows(), current_sizes[i] + 1) 
                << "we are expecting to have one more entry now for session " 
                << added->second << " should have " << (current_sizes[i] + 1) << ", got " << added->second.upstream_flows();
            current_sizes[i]++;
            ASSERT_EQ(added->second.downstream_flows(), 0);
            ASSERT_FALSE(added->second.done()) << "flow " << f << " is not the last one";
        }
        ++i;
    }

    // now we will try one more time, in this case, it will not be able to add for any of the sessions
    i = 0;
    for (auto& f :  client_flows) {
        f.app_data = data_flow::application_data(DELTA_FROM_MAX_SIZE, '1');  // so we are 10 short to be blocked
        auto added = repo.add_flow(f);
        // we cannot add more data to any
        ASSERT_EQ(added, repo.end()) << "failed to add flow " << f;
        ++i;
    }
    // but we must make sure that we can add the closing packet
    i = 0;
    for (auto& f :  client_flows) {
        f.tcp_layer.state.fin = true;
        f.app_data = {};
        auto added = repo.add_flow(f);
        ASSERT_NE(added, repo.end()) << "fail to add flow " << f;
        ASSERT_FALSE(added->second.done()) << "flow " << f << " is not the last one";
        ASSERT_EQ(added->second.upstream_flows(), current_sizes[i] + 1) 
            << "we should add one more entry for the packet that mark as disconnect  but we have size " 
            << added->second.upstream_flows() << " and not " << (current_sizes[i] + 1) << " for " << added->second;
        ASSERT_TRUE(added->second.downstream_flows()  == 0);
        i++;
    }

    // we still need to make sure that this will be useful by mean of closing the session
    // for that we must have the server side as well.
    std::vector<data_flow> server_flows(client_flows);
    for (auto& f : server_flows) {
        std::swap(f.tcp_layer.source_port, f.tcp_layer.dest_port);
        std::swap(f.ipv4_layer.source, f.ipv4_layer.dest);
        f.tcp_layer.state.ack = true;
        f.tcp_layer.state.syn = true;
        f.tcp_layer.state.fin = false;
        f.app_data = {};
        auto added = repo.add_flow(f);
        ASSERT_NE(added, repo.end()) << "fail to add flow " << f;
        ASSERT_EQ(repo.saved(), client_flows.size());   // no new flow
        ASSERT_FALSE(added->second.done());
    }
    // now add the close connection flow from the server side to ensure that we are closing the connection
    for (auto& f : server_flows) {
        f.tcp_layer.state.syn = false;
        f.tcp_layer.state.fin = true;
        auto added = repo.add_flow(f);
        ASSERT_NE(added, repo.end()) << "fail to add flow " << f;
        ASSERT_EQ(repo.saved(), client_flows.size());   // no new flow
        ASSERT_TRUE(added->second.done());
    }

}

TEST(TestMemoryLimits, TestGlobalMemoryUsage) {
    set_log_severity({{DEFAULT_HTTP_CHANNEL, severity_level::critical}});
    // for this test we are adding just a single session, since we can
    // only simulate it with capture, we will just make sure that
    // we can add packets, then we stop, and when we remove, we can do it again.
    auto total_messages_size = calculate_payload_size();
    ASSERT_NE(total_messages_size, 0) << "we failed to calculate the size of the payload that would be generate for this test";
    monitor::default_channel ch;
    pcap* handle = nullptr; // we don't really have one..
    std::uint64_t max_memory = total_messages_size - 1; // bytes
    std::uint64_t max_msg = 1024 * 1024;    // we don't want the message size to be the limiting factor
    //monitor::network_capture::monitor_handler monitor(monitor::write_only_channel{ch});
    monitor::network_capture::monitor_handler::memory_usage mc;
    monitor::network_capture::monitor_handler::internal_channel com;
    monitor::default_channel dummy;
    mc.start(max_memory); // just some random memory limit, we don't really checking this

    monitor::network_capture::monitor_handler::network_device cap_dev{&mc, com};
    monitor::network_capture::monitor_handler::sessions_device session_dev{&mc, com, dummy};

    cap_dev.setup(handle, "some-dev-name"); // just make sure that this is not "any"
    session_dev.setup(max_msg, {});
    
    auto add_packet = [&cap_dev, &session_dev] (tests::packet_data_t packet) {
        auto header = tests::make_pcap_header(std::uint32_t(packet.size()));
        const auto res = cap_dev.try_from(&header, packet.data());
        EXPECT_TRUE(res.is_ok()) << "failed to add packet to monitoring: " << res;
        return session_dev.process(std::move(res.unwrap()));
        //return Ok(res).value();
    };

    auto entry = add_packet(tests::client_connect_packet());
    ASSERT_EQ(session_dev.live_data().saved(), 1);
    ASSERT_TRUE(entry->second.downstream_flows()  == 0);
    ASSERT_EQ(entry->second.upstream_flows(), 1);
    entry = add_packet(tests::server_accept_packet());
    ASSERT_EQ(session_dev.live_data().saved(), 1);
    ASSERT_EQ(entry->second.downstream_flows() , 1);
    ASSERT_EQ(entry->second.upstream_flows(), 1);
    entry = add_packet(tests::client_ack_packet());    //this one is ignored
    entry = add_packet(tests::client_http_get_packet());
    ASSERT_EQ(entry->second.downstream_flows() , 1);
    ASSERT_EQ(entry->second.upstream_flows(), 2);
    entry = add_packet(tests::server_ack_packet());      // this packet is not save
    entry = add_packet(tests::server_http_response_http_headers());
    ASSERT_EQ(entry->second.downstream_flows() , 2);
    ASSERT_EQ(entry->second.upstream_flows(), 2);
    // the next packet should not be added since we are over the limit of the data we have so far
    auto current_mem_usage = entry->second.payloads_memory();
    auto required_memory = packet_memory(tests::server_http_response_http_body());
    ASSERT_GT(required_memory + current_mem_usage, max_memory) 
        << "we are expecting that the next packet with memory payload size " << required_memory 
        << " plus the memory usage " << current_mem_usage <<" so far is larger than " << max_memory;
    entry = add_packet(tests::server_http_response_http_body());
    ASSERT_EQ(session_dev.live_data().begin()->second.downstream_flows() , 3);     // same number of saved packets
    ASSERT_EQ(session_dev.live_data().begin()->second.upstream_flows(), 2);       // for both ways
    current_mem_usage = mc.mem_usage();
    
    ASSERT_EQ(session_dev.live_data().begin()->second.payloads_memory(), current_mem_usage) 
        << "memory usage should be changed!, but we have " << entry->second.payloads_memory()<<", and not " << current_mem_usage;
    // now we can add the next two packet to finish the flow and it should work
    entry = add_packet(tests::client_tcp_close_packet());
    ASSERT_EQ(entry->second.downstream_flows() , 3);
    ASSERT_EQ(entry->second.upstream_flows(), 3);
    
    entry = add_packet(tests::server_tcp_close_packet());
    
    ASSERT_EQ(entry->second.downstream_flows() , 4);
    ASSERT_EQ(entry->second.upstream_flows(), 3);
    ASSERT_TRUE(entry->second.done()) << "should now marked as finished";
}

