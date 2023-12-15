#include "test_ut/http_packet_capture_ut_data.h"
#include "capture_info.h"
#include "session.h"
#ifdef ENABLE_VLAN_UT
# include "capture.h"
# include "channel.h"
#endif  // ENABLE_VLAN_UT
#include "Log/logging.h"
#include <pcap.h>
#include <gtest/gtest.h>
#include <ctime>

namespace 
{

auto stringify_packet = [] (tests::packet_data_t from) -> std::string {
    auto bytes_count = std::min(std::size(from), 64lu);
    auto start = from.data();
    std::ostringstream p;
    while (bytes_count) {
      auto cur = *start;
      p << "0x" << std::setw(2) << std::setfill('0') << std::hex << (std::uint16_t)cur <<" ";
      ++start;
      --bytes_count;
    }
    return p.str();
  };



constexpr auto cast_size(const tests::packet_data_t& from) -> std::uint32_t {
  return std::uint32_t(std::size(from));
}

} // end of local namespace


// Tests here are about packet parsing - note the raw intput from wireshark above
// we would like to make sure that we can successfully parse packets and save them
TEST(HttpCaptureTest, TcpClientConnect) {
  set_log_severity({{DEFAULT_HTTP_CHANNEL, severity_level::critical}});
  // The input packet is the first packet that the client is sending when connecting to the remote server
  monitor::sessions_repo repo;
  ASSERT_EQ(repo.empty(), true);
  ASSERT_EQ(repo.begin(), repo.end());
  ASSERT_EQ(repo.saved(), 0);

  const auto connect_packet = tests::client_connect_packet();
  const auto pcap_header = tests::make_pcap_header(cast_size(connect_packet));
  auto parse_result = monitor::from_capture(&pcap_header, connect_packet.data(), monitor::ethernet_header_len());
  ASSERT_NE(parse_result, std::nullopt);  // should successfully parse the result
  const auto parse_packet = parse_result.value();
  ASSERT_FALSE(parse_packet.has_payload()) << "this should not have payload: " << parse_packet;
  ASSERT_FALSE(parse_packet.acked()) << "this should not have ack " << parse_packet;
  ASSERT_FALSE(parse_packet.fin_sent()) << "this should not have fin " << parse_packet;
  ASSERT_FALSE(parse_packet.control_only()) << "this is not control packet: " << parse_packet;
  ASSERT_FALSE(parse_packet.is_reseting()) << "this should have no reset in it " << parse_packet;
  ASSERT_TRUE(parse_packet.syn_packet()) << "this should have syn in it: " << parse_packet; // first packet is always with syn in TCP
  ASSERT_EQ(parse_packet.tcp_layer.dest_port, tests::EXPECTED_DEST_PORT);
  ASSERT_EQ(parse_packet.tcp_layer.source_port, tests::EXPECTED_SOURCE_PORT);
  ASSERT_EQ(monitor::to_string(parse_packet.ipv4_layer.dest), tests::EXPECTED_DEST_IP);
  ASSERT_EQ(monitor::to_string(parse_packet.ipv4_layer.source), tests::EXPECTED_SOURCE_IP);
  auto insert_result = repo.add_flow(std::move(parse_packet));
  ASSERT_EQ(insert_result, repo.begin());
  ASSERT_FALSE(repo.empty());
  ASSERT_EQ(repo.saved(), 1);
  ASSERT_NE(repo.begin(), repo.end());
  ASSERT_EQ(repo.begin()->second.upstream_flows(), 1);
  ASSERT_EQ(repo.begin()->second.downstream_flows(), 0);
  ASSERT_FALSE(repo.begin()->second.done());
}

TEST(HttpCaptureTest, AcceptBeforeConnect) {
  set_log_severity({{DEFAULT_HTTP_CHANNEL, severity_level::critical}});
  monitor::sessions_repo repo;
  const auto accept_packet = tests::server_accept_packet();
  auto pcap_header = tests::make_pcap_header(cast_size(accept_packet));
  // we are inserting only the connection from the server side.
  // this is not normal but it maybe that we are missing the first flow.
  // to make sure that we are not missing connections, this will add a flow
  // to the upstream as well.
  auto parse_result = monitor::from_capture(&pcap_header, accept_packet.data(), monitor::ethernet_header_len());
  ASSERT_NE(parse_result, std::nullopt);  // should successfully parse the result
  auto parse_packet = parse_result.value();
  auto insert_result = repo.add_flow(parse_packet);
  ASSERT_NE(insert_result, repo.end()) << "we expecting that flow " << parse_packet << ", will return end, but it didn't";
  ASSERT_EQ(repo.saved(), 1);
  ASSERT_NE(repo.begin(), repo.end());
  ASSERT_FALSE(insert_result->second.connection_id().acked());
  ASSERT_TRUE(insert_result->second.connection_id().syn_packet());
  ASSERT_EQ(insert_result->second.connection_id().ipv4_layer.dest,  parse_packet.ipv4_layer.source);
  ASSERT_EQ(insert_result->second.connection_id().ipv4_layer.source,  parse_packet.ipv4_layer.dest);
  ASSERT_EQ(insert_result->second.downstream_id().tcp_layer.source_port, parse_packet.tcp_layer.source_port);
  ASSERT_EQ(insert_result->second.downstream_id().tcp_layer.dest_port, parse_packet.tcp_layer.dest_port);
  ASSERT_EQ(insert_result->second.downstream_id().ipv4_layer.dest, parse_packet.ipv4_layer.dest);
  ASSERT_EQ(insert_result->second.downstream_id().ipv4_layer.source, parse_packet.ipv4_layer.source);
  ASSERT_EQ(insert_result->second.connection_id().tcp_layer.source_port, parse_packet.tcp_layer.dest_port);
  ASSERT_EQ(insert_result->second.connection_id().tcp_layer.dest_port, parse_packet.tcp_layer.source_port);
}

TEST(HttpCaptureTest, InvalidDoubleConnect) {
  set_log_severity({{DEFAULT_HTTP_CHANNEL, severity_level::critical}});
  monitor::sessions_repo repo;
  // try to reinsert same sync packet
  const auto connect_packet = tests::client_connect_packet();
  auto pcap_header = tests::make_pcap_header(cast_size(connect_packet));
  auto parse_result = monitor::from_capture(&pcap_header, connect_packet.data(), monitor::ethernet_header_len());
  auto insert_result = repo.add_flow(std::move(parse_result.value()));
  // at this point must have a valid entry
  ASSERT_EQ(insert_result, repo.begin());
  ASSERT_FALSE(repo.empty());
  ASSERT_EQ(repo.saved(), 1);
  ASSERT_NE(repo.begin(), repo.end());
  ASSERT_EQ(repo.begin()->second.upstream_flows(), 1);
  ASSERT_EQ(repo.begin()->second.downstream_flows(), 0);
  // now we should fail on trying to insert the same packet again
  // as this packet is a syn packet that we already seen
  parse_result = monitor::from_capture(&pcap_header, connect_packet.data(), monitor::ethernet_header_len());
  ASSERT_NE(parse_result, std::nullopt);
  auto parse_packet = parse_result.value();
  insert_result = repo.add_flow(std::move(parse_packet));
  ASSERT_EQ(insert_result, repo.end()) << "this packet " << parse_result.value() << " should not be added"; 
  ASSERT_EQ(repo.saved(), 1);
  ASSERT_EQ(repo.begin()->second.upstream_flows(), 1);
  ASSERT_EQ(repo.begin()->second.downstream_flows(), 0);
  ASSERT_FALSE(repo.begin()->second.done());
}

TEST(HttpCaptureTest, TestServerAccept) {
  set_log_severity({{DEFAULT_HTTP_CHANNEL, severity_level::critical}});
  monitor::sessions_repo repo;
  // insert the first client packet
  const auto connect_packet = tests::client_connect_packet();
  auto pcap_header = tests::make_pcap_header(cast_size(connect_packet));
  auto parse_result = monitor::from_capture(&pcap_header, connect_packet.data(), monitor::ethernet_header_len());
  auto insert_result = repo.add_flow(std::move(parse_result.value()));
  ASSERT_EQ(insert_result, repo.begin()) << "the resulting of adding " << parse_result.value() << " should be successful";
  ASSERT_NE(repo.begin(), repo.end());
  ASSERT_EQ(repo.begin()->second.upstream_flows(), 1);
  ASSERT_EQ(repo.begin()->second.downstream_flows(), 0);
  // now insert the server reply
  const auto accept_packet = tests::server_accept_packet();
  pcap_header = tests::make_pcap_header(cast_size(accept_packet));
  parse_result = monitor::from_capture(&pcap_header, accept_packet.data(), monitor::ethernet_header_len());
  ASSERT_NE(parse_result, std::nullopt);  // should successfully parse the result
  auto parse_packet = parse_result.value();
  ASSERT_FALSE(parse_packet.has_payload()) << "packet " << parse_packet << " should not have payload";
  ASSERT_TRUE(parse_packet.acked()) << "packet " << parse_packet << " should have ack";
  ASSERT_FALSE(parse_packet.fin_sent()) << "packet " << parse_packet << " should not have fin";
  ASSERT_FALSE(parse_packet.control_only()) << "packet " << parse_packet << " is not a control packet";
  ASSERT_FALSE(parse_packet.is_reseting()) << "packet " << parse_packet << " should not have reset";
  ASSERT_TRUE(parse_packet.syn_packet()); // first packet is always with syn in TCP
  ASSERT_EQ(parse_packet.tcp_layer.dest_port, tests::EXPECTED_SOURCE_PORT);
  ASSERT_EQ(parse_packet.tcp_layer.source_port, tests::EXPECTED_DEST_PORT);
  ASSERT_EQ(monitor::to_string(parse_packet.ipv4_layer.dest), tests::EXPECTED_SOURCE_IP);
  ASSERT_EQ(monitor::to_string(parse_packet.ipv4_layer.source), tests::EXPECTED_DEST_IP);
  auto state = parse_packet.tcp_layer.connection_state();
  ASSERT_EQ(state, monitor::TCP::current_state::ACK_START_CONNECT);
  insert_result = repo.add_flow(std::move(parse_packet));
  ASSERT_NE(insert_result, repo.end()) << "failed to add " << parse_result.value();
  ASSERT_EQ(repo.begin()->second.upstream_flows(), 1);
  ASSERT_EQ(repo.begin()->second.downstream_flows(), 1); 
  ASSERT_EQ(repo.saved(), 1);   // still a single flow
  ASSERT_FALSE(repo.begin()->second.done());
}

TEST(HttpCaptureTest, TestIgnoreClientPacket) {
  set_log_severity({{DEFAULT_HTTP_CHANNEL, severity_level::critical}});
  // we are ignoring a packet that don't have a data in it,
  // and its not the first or the last one, these packets that only 
  // serve as ACK packets can be ignored
  monitor::sessions_repo repo;
  const auto ack_only_client_packet = tests::client_ack_packet();
  auto pcap_header = tests::make_pcap_header(cast_size(ack_only_client_packet));
  auto parse_result = monitor::from_capture(&pcap_header, ack_only_client_packet.data(), monitor::ethernet_header_len());
  ASSERT_NE(parse_result, std::nullopt);  // should successfully parse the result
  auto parse_packet = parse_result.value();
  ASSERT_FALSE(parse_packet.has_payload());
  ASSERT_TRUE(parse_packet.acked());
  ASSERT_FALSE(parse_packet.fin_sent());
  ASSERT_TRUE(parse_packet.control_only());
  ASSERT_FALSE(parse_packet.is_reseting());
  ASSERT_FALSE(parse_packet.syn_packet()); // first packet is always with syn in TCP
  ASSERT_EQ(parse_packet.tcp_layer.dest_port, tests::EXPECTED_DEST_PORT);
  ASSERT_EQ(parse_packet.tcp_layer.source_port, tests::EXPECTED_SOURCE_PORT);
  ASSERT_EQ(monitor::to_string(parse_packet.ipv4_layer.dest), tests::EXPECTED_DEST_IP);
  ASSERT_EQ(monitor::to_string(parse_packet.ipv4_layer.source), tests::EXPECTED_SOURCE_IP);
  auto state = parse_packet.tcp_layer.connection_state();
  ASSERT_EQ(state, monitor::TCP::current_state::ACK_STATE);
  // now try to add this packet, note that this packet cannot be added to empty since
  // this is not the first packet in a session
  auto ack_only = parse_packet;
  auto insert_result = repo.add_flow(std::move(parse_packet));
  ASSERT_EQ(insert_result, repo.end());
  ASSERT_TRUE(repo.empty());
  // add the first valid packet
  const auto connect_packet = tests::client_connect_packet();
  pcap_header = tests::make_pcap_header(cast_size(connect_packet));
  parse_result = monitor::from_capture(&pcap_header, connect_packet.data(), monitor::ethernet_header_len());
  ASSERT_NE(parse_result, std::nullopt);  // should successfully parse the result
  parse_packet = parse_result.value();
  insert_result = repo.add_flow(std::move(parse_packet));
  ASSERT_NE(insert_result, repo.end());
  ASSERT_EQ(repo.begin()->second.upstream_flows(), 1);
  ASSERT_FALSE(repo.empty());
  // and try again to add this packet, it should not work, since we don't care about it
  insert_result = repo.add_flow(std::move(ack_only));
  ASSERT_EQ(insert_result, repo.end());
  ASSERT_EQ(repo.begin()->second.upstream_flows(), 1);
  ASSERT_FALSE(repo.begin()->second.done());
}

TEST(HttpCaptureTest, TestFirstPacketHttpGet) {
  set_log_severity({{DEFAULT_HTTP_CHANNEL, severity_level::critical}});
  // In this test we will add a packet with HTTP GET payload in it
  const auto http_get_client_packet = tests::client_http_get_packet();
  auto pcap_header = tests::make_pcap_header(cast_size(http_get_client_packet));
   auto parse_result = monitor::from_capture(&pcap_header, http_get_client_packet.data(), monitor::ethernet_header_len());
  ASSERT_NE(parse_result, std::nullopt);  // should successfully parse the result
  auto parse_packet = parse_result.value();
  ASSERT_TRUE(parse_packet.has_payload());
  ASSERT_TRUE(parse_packet.acked());
  ASSERT_FALSE(parse_packet.fin_sent());
  ASSERT_FALSE(parse_packet.control_only());
  ASSERT_FALSE(parse_packet.is_reseting());
  ASSERT_FALSE(parse_packet.syn_packet()); // first packet is always with syn in TCP
  ASSERT_EQ(parse_packet.tcp_layer.dest_port, tests::EXPECTED_DEST_PORT);
  ASSERT_EQ(parse_packet.tcp_layer.source_port, tests::EXPECTED_SOURCE_PORT);
  ASSERT_EQ(monitor::to_string(parse_packet.ipv4_layer.dest), tests::EXPECTED_DEST_IP);
  ASSERT_EQ(monitor::to_string(parse_packet.ipv4_layer.source), tests::EXPECTED_SOURCE_IP);
  auto state = parse_packet.tcp_layer.connection_state();
  ASSERT_EQ(state, monitor::TCP::current_state::ACK_STATE);
  // trying to add this is OK, since we are allowing to add only HTTP GET packet
  monitor::sessions_repo repo;
  auto http_get = parse_packet;
  auto insert_result = repo.add_flow(std::move(parse_packet));
  ASSERT_NE(insert_result, repo.end());
  ASSERT_FALSE(repo.empty());
}

TEST(HttpCaptureTest, TestAddClientPayloadPacket) {  
  set_log_severity({{DEFAULT_HTTP_CHANNEL, severity_level::critical}});
  monitor::sessions_repo repo;
  const auto tcp_close = tests::client_tcp_close_packet();
  auto pcap_header = tests::make_pcap_header(cast_size(tcp_close));
  auto parse_result = monitor::from_capture(&pcap_header, tcp_close.data(), monitor::ethernet_header_len());
  ASSERT_NE(parse_result, std::nullopt);  // should successfully parse the result
  auto parse_packet = parse_result.value();
  auto insert_result = repo.add_flow(std::move(parse_packet));
  ASSERT_EQ(insert_result, repo.end());
  ASSERT_TRUE(repo.empty());
  // now add the first valid flow for a session
  const auto connect_packet = tests::client_connect_packet();
  pcap_header = tests::make_pcap_header(cast_size(connect_packet));
  parse_result = monitor::from_capture(&pcap_header, connect_packet.data(), monitor::ethernet_header_len());
  ASSERT_NE(parse_result, std::nullopt);  // should successfully parse the result
  parse_packet = parse_result.value();
  insert_result = repo.add_flow(std::move(parse_packet));
  ASSERT_NE(insert_result, repo.end());
  ASSERT_EQ(repo.begin()->second.upstream_flows(), 1);
  ASSERT_FALSE(repo.empty());
  // and try again, this time it should work
  const auto http_get_client_packet = tests::client_http_get_packet();
  pcap_header = tests::make_pcap_header(cast_size(http_get_client_packet));
  parse_result = monitor::from_capture(&pcap_header, http_get_client_packet.data(), monitor::ethernet_header_len());
  ASSERT_NE(parse_result, std::nullopt);  // should successfully parse the result
  parse_packet = parse_result.value();
  ASSERT_TRUE(parse_packet.has_payload());
  auto http_get = parse_packet;
  insert_result = repo.add_flow(std::move(http_get));
  ASSERT_NE(insert_result, repo.end());
  ASSERT_EQ(repo.begin()->second.upstream_flows(), 2);
  ASSERT_FALSE(repo.begin()->second.done());
}

TEST(HttpCaptureTest, TestServerAckOnlyPacket) {
  set_log_severity({{DEFAULT_HTTP_CHANNEL, severity_level::critical}});
  // for this test we have a message from the server that
  // only contain ack, just like in the client case, we just
  // discard this message, since it contain no interesting info for us
  const auto server_ack_packet = tests::server_ack_packet();
  auto pcap_header = tests::make_pcap_header(cast_size(server_ack_packet));
  auto parse_result = monitor::from_capture(&pcap_header, server_ack_packet.data(), monitor::ethernet_header_len());
  ASSERT_NE(parse_result, std::nullopt);  // should successfully parse the result
  auto parse_packet = parse_result.value();
  ASSERT_FALSE(parse_packet.has_payload());
  ASSERT_TRUE(parse_packet.acked());
  ASSERT_FALSE(parse_packet.fin_sent());
  ASSERT_TRUE(parse_packet.control_only());
  ASSERT_FALSE(parse_packet.is_reseting());
  ASSERT_FALSE(parse_packet.syn_packet()); // first packet is always with syn in TCP
  ASSERT_EQ(parse_packet.tcp_layer.dest_port, tests::EXPECTED_SOURCE_PORT);
  ASSERT_EQ(parse_packet.tcp_layer.source_port, tests::EXPECTED_DEST_PORT);
  ASSERT_EQ(monitor::to_string(parse_packet.ipv4_layer.dest), tests::EXPECTED_SOURCE_IP);
  ASSERT_EQ(monitor::to_string(parse_packet.ipv4_layer.source), tests::EXPECTED_DEST_IP);
  auto state = parse_packet.tcp_layer.connection_state();
  ASSERT_EQ(state, monitor::TCP::current_state::ACK_STATE);
  // try inserting this as the first packet, it should reject
  monitor::sessions_repo repo;
  auto server_ack = parse_packet;
  auto insert_result = repo.add_flow(std::move(parse_packet));
  ASSERT_EQ(insert_result, repo.end());
  ASSERT_TRUE(repo.empty());
  // now place a valid first message, see how this one goes..
  const auto connect_packet = tests::client_connect_packet();
  pcap_header = tests::make_pcap_header(cast_size(connect_packet));
  parse_result = monitor::from_capture(&pcap_header, connect_packet.data(), monitor::ethernet_header_len());
  ASSERT_NE(parse_result, std::nullopt);  // should successfully parse the result
  parse_packet = parse_result.value();
  insert_result = repo.add_flow(std::move(parse_packet));
  ASSERT_NE(insert_result, repo.end());
  ASSERT_EQ(repo.begin()->second.upstream_flows(), 1);
  ASSERT_FALSE(repo.empty());
  // now add the packet, it should fail..
  auto server_ack2 = server_ack;
  insert_result = repo.add_flow(std::move(server_ack));
  ASSERT_EQ(insert_result, repo.end());
  ASSERT_EQ(repo.begin()->second.downstream_flows(), 0); 
  // try with downstream packet as well
  const auto accept_packet = tests::server_accept_packet();
  pcap_header = tests::make_pcap_header(cast_size(accept_packet));
  parse_result = monitor::from_capture(&pcap_header, accept_packet.data(), monitor::ethernet_header_len());
  parse_packet = parse_result.value();
  insert_result = repo.add_flow(std::move(parse_packet));
  ASSERT_NE(insert_result, repo.end());
  ASSERT_EQ(repo.begin()->second.downstream_flows(), 1); 
  // and even when we have downstream packet it should still fail
  // since this packet is control packet
  insert_result = repo.add_flow(std::move(server_ack2));
  ASSERT_EQ(insert_result, repo.end());
  ASSERT_EQ(repo.begin()->second.downstream_flows(), 1); 
  ASSERT_FALSE(repo.begin()->second.done());
}

TEST(HttpCaptureTest, TestServerHttpOk) {
  set_log_severity({{DEFAULT_HTTP_CHANNEL, severity_level::critical}});
  // This will handle a packet with the reply from
  // the server on the HTTP GET packet
  const auto http_ok_server_packet = tests::server_http_response_http_headers();
  auto pcap_header = tests::make_pcap_header(cast_size(http_ok_server_packet));
  auto parse_result = monitor::from_capture(&pcap_header, http_ok_server_packet.data(), monitor::ethernet_header_len());
  ASSERT_NE(parse_result, std::nullopt);  // should successfully parse the result
  auto parse_packet = parse_result.value();
  ASSERT_TRUE(parse_packet.has_payload());
  ASSERT_TRUE(parse_packet.acked());
  ASSERT_FALSE(parse_packet.fin_sent());
  ASSERT_FALSE(parse_packet.control_only());
  ASSERT_FALSE(parse_packet.is_reseting());
  ASSERT_FALSE(parse_packet.syn_packet()); // first packet is always with syn in TCP
  ASSERT_EQ(parse_packet.tcp_layer.dest_port, tests::EXPECTED_SOURCE_PORT);
  ASSERT_EQ(parse_packet.tcp_layer.source_port, tests::EXPECTED_DEST_PORT);
  ASSERT_EQ(monitor::to_string(parse_packet.ipv4_layer.dest), tests::EXPECTED_SOURCE_IP);
  ASSERT_EQ(monitor::to_string(parse_packet.ipv4_layer.source), tests::EXPECTED_DEST_IP);
  auto state = parse_packet.tcp_layer.connection_state();
  ASSERT_EQ(state, monitor::TCP::current_state::ACK_STATE);
  // we cannot insert this packet since this packet is not part of the TCP handshake
  // make sure that this is true
  auto http_sever_ack = parse_result;
  monitor::sessions_repo repo;
  auto insert_result = repo.add_flow(std::move(parse_packet));
  ASSERT_EQ(insert_result, repo.end());
  ASSERT_TRUE(repo.empty());
  // add the TCP client sync and try again
  const auto connect_packet = tests::client_connect_packet();
  pcap_header = tests::make_pcap_header(cast_size(connect_packet));
  parse_result = monitor::from_capture(&pcap_header, connect_packet.data(), monitor::ethernet_header_len());
  ASSERT_NE(parse_result, std::nullopt);  // should successfully parse the result
  parse_packet = parse_result.value();
  insert_result = repo.add_flow(std::move(parse_packet));
  ASSERT_NE(insert_result, repo.end());
  ASSERT_EQ(repo.begin()->second.upstream_flows(), 1);
  ASSERT_FALSE(repo.empty());
  auto http_sever_ack2 = http_sever_ack;
  insert_result = repo.add_flow(std::move(http_sever_ack.value()));
  ASSERT_NE(insert_result, repo.end());
  ASSERT_NE(repo.begin()->second.downstream_flows(), 0);
  // we cannot add server syn any more, we "manually" added it
  const auto accept_packet = tests::server_accept_packet();
  pcap_header = tests::make_pcap_header(cast_size(accept_packet));
  parse_result = monitor::from_capture(&pcap_header, accept_packet.data(), monitor::ethernet_header_len());
  parse_packet = parse_result.value();
  insert_result = repo.add_flow(std::move(parse_packet));
  ASSERT_EQ(insert_result, repo.end());
  ASSERT_EQ(repo.begin()->second.downstream_flows(), 2);
  // now it should work
  insert_result = repo.add_flow(std::move(http_sever_ack2.value()));
  ASSERT_NE(insert_result, repo.end());
  ASSERT_EQ(repo.begin()->second.downstream_flows(), 3);
  ASSERT_FALSE(repo.begin()->second.done());
}

TEST(HttpCaptureTest, FullFlow) {
  set_log_severity({{DEFAULT_HTTP_CHANNEL, severity_level::critical}});
  // In this test we are generating a valid flow, i.e
  // client -> server connect
  // server -> client accept
  // client -> server ack
  // server -> client ack
  // client -> server http get
  // server -> client http OK
  // client -> server fin
  // server -> client fin ack
  // at the end of this flow we are expecting to see that 
  // we identify this as done
  const tests::packet_data_t flows[] = {
    tests::client_connect_packet(), tests::server_accept_packet(), 
    tests::client_ack_packet(), tests::server_ack_packet(),
    tests::client_http_get_packet(), tests::server_http_response_http_headers(), 
    tests::client_tcp_close_packet(), tests::server_tcp_close_packet()
  };
  auto size = std::size(flows);
  auto last_before_end = size - 1;
  auto index = 0lu;
  monitor::sessions_repo repo;
  for (const auto f : flows) {
    auto pcap_header = tests::make_pcap_header(cast_size(f));
    auto parse_result = monitor::from_capture(&pcap_header, f.data(), monitor::ethernet_header_len());
    ASSERT_NE(parse_result, std::nullopt);  // should successfully parse the result
    auto parse_packet = parse_result.value();
    auto is_control = parse_packet.control_only();
    auto insert_result = repo.add_flow(std::move(parse_packet));
    ASSERT_FALSE(repo.empty()) <<" we are expecting to have none empty repo after " << index << " iterations" << std::endl;
    ASSERT_EQ(repo.saved(), 1);
    if (is_control) {
      ASSERT_EQ(insert_result, repo.end());
    } else {
      ASSERT_NE(insert_result, repo.end());
    }
    if (index != last_before_end) {
      ASSERT_FALSE(repo.begin()->second.done());
    } else {
      ASSERT_TRUE(repo.begin()->second.done());
    }
    index++;
  }
}

TEST(HttpCaptureTest, TestIgnoreSSL) {
  // this will test that we can identify SSL packet and to not save them
  // the reason for this is that packet that are encrypted cannot be parsed
  set_log_severity({{DEFAULT_HTTP_CHANNEL, severity_level::critical}});
  // With SSL we have the flow of
  // TCP client connect
  // TCP server accept
  // SSL client hello
  // TCP server ack
  // SSL serer hello
  // other SSL staff
  // TCP client close
  // TCP server close
    //             message              saved? encrypted
  const std::tuple<tests::packet_data_t, bool, bool> flows[] = {
    {tests::client_connect_with_tls(), true, false},
    {tests::server_accept_with_tls(), true, false},
    {tests::client_ack_with_tls(), false, false},
    {tests::client_hello_with_tls(), true, true},
    {tests::serer_ack_with_tls(), false, false},
    {tests::server_hello_with_tls(), true, true},
    {tests::client_ack_with_tls(), false, false},
    {tests::client_cipher_with_tls(), false, true},
    {tests::client_app_with_tls(), false, true},
    {tests::server_app_with_tls(), false, true},
    {tests::server_app_data_large(), false, true},
    {tests::client_app_with_tls(), false, true},
    {tests::server_app_data_large(), false, true},
    {tests::client_ack_with_tls(), false, false},
    {tests::client_cipher_with_tls(), false, true},
    {tests::server_app_with_tls(), false, true}
  };
  // note that we are not at the end of the session, we are missing
  // the closing packets, we will deal with it later
  monitor::sessions_repo repo;
  std::size_t expected_payload = 0;
  int i = 0;
  std::uint64_t flow_id = 0;
  for (const auto& f : flows) {
    i++;
    const bool should_save = std::get<1>(f);
    const bool is_encrypted = std::get<2>(f);
    const tests::packet_data_t msg = std::get<0>(f);
    auto pcap_header = tests::make_pcap_header(cast_size(msg));
    auto parse_result = monitor::from_capture(&pcap_header, msg.data(), monitor::ethernet_header_len());
    ASSERT_NE(parse_result, std::nullopt) << i << ": failed to parse packet " << stringify_packet(msg);  // should successfully parse the result
    auto parse_packet = parse_result.value();
    if (is_encrypted) {
      ASSERT_TRUE(parse_packet.is_encrypted()) << i <<": packet " << parse_packet << " should be encrypted, but we failed to identify it as such";
    } else {
      ASSERT_FALSE(parse_packet.is_encrypted()) << i <<  ": packet " << parse_packet << " should not be identify as encrypted, but we think it is";
    }
    auto is_control = parse_packet.control_only();
    flow_id = monitor::make_id(parse_packet);
    auto insert_result = repo.add_flow(std::move(parse_packet));
    if (should_save) {
      ASSERT_NE(insert_result, repo.end()) << i << ": we are expecting that for packet " << parse_result.value() << " we will save successfully";
      expected_payload += parse_result.value().payload_size();
    } else {
      if (is_encrypted) {
        ASSERT_FALSE(is_control) << i << " expecting control message for " << parse_result.value(); 
      }
      if (is_control) {
        ASSERT_FALSE(is_encrypted) << i << " expecting that control message is not encrypted: " << parse_result.value();
      }
      ASSERT_EQ(insert_result, repo.end()) << i << " should not successfully saved: " << parse_result.value();
    }
  }
  ASSERT_NE(flow_id, 0) << "we don't have the flow id!!";
  ASSERT_EQ(repo.saved(), 1) << "should only have a single flow in the repo";
  ASSERT_EQ(repo.sessions[flow_id].upstream_flows(), 2);
  ASSERT_EQ(repo.sessions[flow_id].downstream_flows(), 2);
  ASSERT_TRUE(repo.begin()->second.is_encrypted());  // make sure we know that this is indeed encrypted
  ASSERT_FALSE(repo.begin()->second.done()) << "we are not done yet, we are missing the final packets";

  // now lets see if we can add "normal" - i.e. none encrypted packets and see that its all good and well
  const tests::packet_data_t none_encrypted_flows[] = {
    tests::client_connect_packet(), tests::server_accept_packet(), 
    tests::client_ack_packet(), tests::server_ack_packet(),
    tests::client_http_get_packet(), tests::server_http_response_http_headers(), 
    tests::client_tcp_close_packet(), tests::server_tcp_close_packet()
  };
  auto size = std::size(flows);
  auto last_before_end = size - 1;
  auto index = 0lu;
  std::uint64_t flow_index = 0;
  for (const auto f : none_encrypted_flows) {
    auto pcap_header = tests::make_pcap_header(cast_size(f));
    auto parse_result = monitor::from_capture(&pcap_header, f.data(), monitor::ethernet_header_len());
    ASSERT_NE(parse_result, std::nullopt);  // should successfully parse the result
    auto parse_packet = parse_result.value();
    auto is_control = parse_packet.control_only();
    ASSERT_FALSE(parse_packet.is_encrypted()) << "the flow " << parse_packet << " is not encrypted, but we identify it as such";
    flow_index = monitor::make_id(parse_packet);
    auto insert_result = repo.add_flow(std::move(parse_packet));
    ASSERT_FALSE(repo.empty()) <<" we are expecting to have none empty repo after " << index << " iterations" << std::endl;
    ASSERT_EQ(repo.saved(), 2);
    if (is_control) {
      ASSERT_EQ(insert_result, repo.end());
    } else {
      ASSERT_NE(insert_result, repo.end());
    }
    if (index != last_before_end) {
      ASSERT_FALSE(repo.begin()->second.done());
    } else {
      ASSERT_TRUE(repo.begin()->second.done());
    }
    index++;
  }
  ASSERT_NE(flow_index, 0) << "no flow index for second flow";
  ASSERT_EQ(repo.saved(), 2); // we now have 2 flows
  ASSERT_FALSE(repo.sessions[flow_index].is_encrypted()) << "second flow is not encrypted";
  ASSERT_TRUE(repo.sessions[flow_index].done()) << "the session at 1, " << repo.sessions[flow_index] << ", should be done";
  // now add the last encrypted messages, this should make the encrypted flow into done
  // state, and then verify that it does
  const tests::packet_data_t closing_encrypted_flows[] = {
    tests::client_close_with_tls(), tests::server_close_with_tls()
  };
  
  for (const auto f : closing_encrypted_flows) {
    auto pcap_header = tests::make_pcap_header(cast_size(f));
    auto parse_result = monitor::from_capture(&pcap_header, f.data(), monitor::ethernet_header_len());
    ASSERT_NE(parse_result, std::nullopt);  // should successfully parse the result
    auto parse_packet = parse_result.value();
    auto is_control = parse_packet.control_only();
    ASSERT_FALSE(is_control) << "this is not a control message: " << parse_packet;
    ASSERT_FALSE(parse_packet.is_encrypted()) << "this is not an encrypted message: " << parse_packet;
    
    auto insert_result = repo.add_flow(std::move(parse_packet));
    ASSERT_NE(insert_result, repo.end()) << "this is a closing message, we should save it";
  }
  ASSERT_EQ(repo.saved(), 2); // we now have 2 flows
  ASSERT_TRUE(repo.begin()->second.done()) << " the first session which is the encrypted session " << repo.begin()->second << ", should be ready now";
  ASSERT_TRUE(repo.sessions[flow_index].done()) << "the second session which is not encrypted should be ready as well";
  ASSERT_TRUE(repo.begin()->second.is_encrypted()) << "the first session: " << repo.begin()->second << " should be encrypted";
  ASSERT_FALSE(repo.sessions[flow_index].is_encrypted()) << "the second session " << repo.sessions[flow_index] << " should not be encrypted";
  // just make sure that we save the correct number of bytes..
  auto encrypt_payload = repo.begin()->second.payloads_memory();
  ASSERT_EQ(expected_payload, encrypt_payload) << "we should have saved " << expected_payload << " bytes, but we are reposing to have " << encrypt_payload;
}

TEST(HttpCaptureTest, TestSSLWithNoSSL) {
  set_log_severity({{DEFAULT_HTTP_CHANNEL, severity_level::critical}});
  // this test will raise the ante - we would like to simulate
  // traffic where we have both encrypted and none encrypted data
  // comping intermixed, to make sure that we don't have an issue
  // processing it
  //                message             should save? encrypted, ssl session
  const std::tuple<tests::packet_data_t, bool,        bool,     bool> flows[] = {
    {tests::client_connect_with_tls(), true, false, true},
    {tests::client_connect_packet(), true, false, false}, 
    {tests::server_accept_with_tls(), true, false, true},
    {tests::client_ack_with_tls(), false, false, true},
    {tests::client_hello_with_tls(), true, true, true},
    {tests::server_accept_packet(), true, false, false},
    {tests::serer_ack_with_tls(), false, false, true},
    {tests::server_hello_with_tls(), true, true, true},
    {tests::client_ack_with_tls(), false, false, true},
    {tests::client_cipher_with_tls(), false, true, true},
    {tests::client_app_with_tls(), false, true, true},
    {tests::client_ack_packet(), false, false, false},
    {tests::server_app_with_tls(), false, true, true},
    {tests::server_ack_packet(), false, false, false},
    {tests::server_app_data_large(), false, true, true},
    {tests::client_app_with_tls(), false, true, true},
    {tests::server_app_data_large(), false, true, true},
    {tests::client_ack_with_tls(), false, false, true},
    {tests::client_http_get_packet(), true, false, false},
    {tests::client_cipher_with_tls(), false, true, true},
    {tests::server_http_response_http_headers(), true, false, false},
    {tests::server_app_with_tls(), false, true, true}
  };
  // note that the by end of processing these flows we would not have anything ready yet
  // but we should have two sessions.
  int i = 0;
  monitor::sessions_repo repo;
  std::size_t expected_payload = 0;
  //const std::size_t ssl_session_index = 0;
  //const std::size_t http_session_index = 1;
  std::uint64_t http_session_id = 0;
  std::uint64_t ssl_session_id = 0;
  std::vector<std::uint64_t> ids;
  for (const auto &[msg, should_save, is_encrypted, is_ssl] : flows) {
    i++;
    auto pcap_header = tests::make_pcap_header(cast_size(msg));
    auto parse_result = monitor::from_capture(&pcap_header, msg.data(), monitor::ethernet_header_len());
    ASSERT_NE(parse_result, std::nullopt) << i << ": failed to parse packet " << stringify_packet(msg);  // should successfully parse the result
    auto parse_packet = parse_result.value();
    if (is_encrypted) {
      ASSERT_TRUE(parse_packet.is_encrypted()) << i <<": packet " << parse_packet << " should be encrypted, but we failed to identify it as such";
    } else {
      ASSERT_FALSE(parse_packet.is_encrypted()) << i <<  ": packet " << parse_packet << " should not be identify as encrypted, but we think it is";
    }
    auto id = monitor::make_id(parse_packet);
    
    auto is_control = parse_packet.control_only();
    if (is_ssl) {
      ssl_session_id = id;
    } else {
      http_session_id = id;
    }
    auto insert_result = repo.add_flow(std::move(parse_packet));
    if (should_save) {
      ASSERT_NE(insert_result, repo.end()) << i << ": we are expecting that for packet " << parse_result.value() << " we will save successfully";
      if (is_encrypted) {
        expected_payload += parse_result.value().payload_size();
      }
    } else {
      if (is_encrypted) {
        ASSERT_FALSE(is_control) << i << " expecting control message for " << parse_result.value(); 
      }
      if (is_control) {
        ASSERT_FALSE(is_encrypted) << i << " expecting that control message is not encrypted: " << parse_result.value();
      }
      ASSERT_EQ(insert_result, repo.end()) <<i << " should not successfully saved: " << parse_result.value();
    }
    if (!is_ssl) {
      EXPECT_EQ(repo.saved(), 2) << "we are expecting to have two sessions as we saved the HTTP flow";
      
      ASSERT_FALSE(repo.sessions[http_session_id].is_encrypted()) << "we are not expecting that it would be identify as encrypted " << repo.sessions[http_session_id];
      ASSERT_FALSE(repo.sessions[http_session_id].done()) << "the HTTP session should not be done yet " << repo.sessions[http_session_id];
    }
    ASSERT_FALSE(repo.sessions[ssl_session_id].done()) << "the HTTP session should not be done yet " << repo.sessions[ssl_session_id];
  }
  ASSERT_EQ(repo.saved(), 2) << "should only have 2 sessions, one for SSL and one for HTTP";
  ASSERT_EQ(repo.sessions[ssl_session_id].upstream_flows(), 2);
  ASSERT_EQ(repo.sessions[ssl_session_id].downstream_flows(), 2);
  ASSERT_TRUE(repo.sessions[ssl_session_id].is_encrypted()) << "this session should be identify as encrypted: " << repo.sessions[ssl_session_id];
  ASSERT_FALSE(repo.sessions[ssl_session_id].done()) << "we are not done yet, we are missing the final packets: " << repo.sessions[ssl_session_id]; 
  ASSERT_EQ(repo.sessions[ssl_session_id].upstream_flows(), 2);
  ASSERT_EQ(repo.sessions[ssl_session_id].downstream_flows(), 2);
  ASSERT_TRUE(repo.sessions[ssl_session_id].is_encrypted()) << "HTTP session is not encrypted: " << repo.sessions[ssl_session_id];
  ASSERT_FALSE(repo.sessions[ssl_session_id].done()) << "we are not done yet, we are missing the final packets" << repo.sessions[ssl_session_id];
  // now close both sessions
  const tests::packet_data_t closing_flows[] = {
    tests::client_close_with_tls(), 
    tests::client_tcp_close_packet(), 
    tests::server_tcp_close_packet(),
    tests::server_close_with_tls()
  };

  for (const auto f : closing_flows) {
    auto pcap_header = tests::make_pcap_header(cast_size(f));
    auto parse_result = monitor::from_capture(&pcap_header, f.data(), monitor::ethernet_header_len());
    ASSERT_NE(parse_result, std::nullopt);  // should successfully parse the result
    auto parse_packet = parse_result.value();
    auto is_control = parse_packet.control_only();
    ASSERT_FALSE(is_control) << "this is not a control message: " << parse_packet;
    ASSERT_FALSE(parse_packet.is_encrypted()) << "this is not an encrypted message: " << parse_packet;
    auto insert_result = repo.add_flow(std::move(parse_packet));
    ASSERT_NE(insert_result, repo.end()) << "this is a closing message, we should save it";
    ASSERT_EQ(repo.saved(), 2) << "number of sessions should be 2 no matter what at this point";
    ASSERT_FALSE(repo.sessions[http_session_id].is_encrypted()) << "HTTP session is not encrypted: " << repo.sessions[http_session_id];
    ASSERT_TRUE(repo.sessions[ssl_session_id].is_encrypted()) << "this session should be identify as encrypted: " << repo.sessions[ssl_session_id];
  }
  // at this point we should have both ready
  ASSERT_EQ(repo.saved(), 2) << "should only have 2 sessions, one for SSL and one for HTTP";
  ASSERT_EQ(repo.sessions[ssl_session_id].upstream_flows(), 3);
  ASSERT_EQ(repo.sessions[ssl_session_id].downstream_flows(), 3);
  ASSERT_TRUE(repo.sessions[ssl_session_id].is_encrypted()) << "this session should be identify as encrypted: " << repo.sessions[ssl_session_id];
  ASSERT_TRUE(repo.sessions[ssl_session_id].done()) << "we should be done: " << repo.sessions[ssl_session_id]; 
  ASSERT_EQ(repo.sessions[ssl_session_id].upstream_flows(), 3);
  ASSERT_EQ(repo.sessions[ssl_session_id].downstream_flows(), 3);
  ASSERT_FALSE(repo.sessions[http_session_id].is_encrypted()) << "HTTP session is not encrypted: " << repo.sessions[ssl_session_id];
  ASSERT_TRUE(repo.sessions[ssl_session_id].done()) << "we should be done:" << repo.sessions[ssl_session_id];
  ASSERT_EQ(expected_payload, repo.sessions[ssl_session_id].payloads_memory()) << "the payload size for the encrypted message should be " << 
    expected_payload << "bytes, but we have  " << repo.sessions[ssl_session_id].payloads_memory() << " bytes";

}
#ifdef ENABLE_VLAN_UT
TEST(HttpCaptureTest, TestVlan) {
    auto payload = tests::traffic_over_vlan();
    auto pcap_header = tests::make_pcap_header(cast_size(payload));
    monitor::network_capture::monitor_handler::internal_channel  ch;
    monitor::network_capture::monitor_handler::memory_usage mc;
    monitor::network_capture::monitor_handler::network_device handler{&mc, ch};
    //auto parse_result = monitor::from_capture(&pcap_header, payload.data(), monitor::ethernet_header_len());
    auto parse_result = handler.process(&pcap_header, payload.data());
    ASSERT_TRUE(parse_result.is_ok()) << "failed to parse packet of type vlan";
}
#endif  // ENABLE_VLAN_UT