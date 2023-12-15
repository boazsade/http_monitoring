include(flags)
include(dependencies)

add_library(http_monitor STATIC           
           capture_info.h  capture_info.cpp 
           capture.h capture.cpp
           channel.h
           processor.h processor.cpp
           formatter.h formatter.cpp
           output_data.h output_data.cpp
           http_match.h http_match.cpp
           session.h session.cpp
           httpclient/httpclient.h httpclient/httpclient.cpp
           utils.h utils.cpp
           http_stream.h http_stream.cpp
	    ) 

list(APPEND EXTRA_INCLUDES httpparser)
list(APPEND EXTRA_INCLUDES httpclient)

#target_include_directories(src PUBLIC ../ )
target_include_directories(http_monitor PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>/../)

enable_testing()
find_package(GTest REQUIRED)
list(APPEND EXTRA_LIBS  Log http_monitor Boost::log  
    Boost::coroutine Boost::thread Boost::context
    pthread pcap dl)

## unit tests
add_subdirectory(test_ut)
add_executable(
  http_packet_monitoring_test
  http_packet_monitor_ut.cpp
)
target_link_libraries(
  http_packet_monitoring_test
  http_packet_monitor_ut_data
  ${EXTRA_LIBS}
  GTest::Main
)

add_executable(
  http_formatter_test
  parse_http_packet_ut.cpp
)

target_link_libraries(
  http_formatter_test
  ${EXTRA_LIBS}
  GTest::Main
)

add_executable(
  match_packet_test
  match_packets_ut.cpp
)
target_link_libraries(
  match_packet_test
  ${EXTRA_LIBS}
  GTest::Main
)

add_executable(
  memory_limits_test
  memory_limits_ut.cpp
)
target_link_libraries(
  memory_limits_test
  http_packet_monitor_ut_data
  ${EXTRA_LIBS}
  GTest::Main
)

include(GoogleTest)
gtest_discover_tests(http_packet_monitoring_test)
gtest_discover_tests(http_formatter_test)
gtest_discover_tests(match_packet_test)
gtest_discover_tests(memory_limits_test)
