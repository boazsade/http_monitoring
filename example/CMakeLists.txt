include(dependencies)
include(flags)
list(APPEND MAIN_FILES
    main.cpp
)

add_executable(sniffer_all  ${MAIN_FILES})
list(APPEND EXTRA_LIBS Log http_monitor Boost::log
    Boost::coroutine Boost::thread Boost::context
    Boost::program_options
    pthread pcap dl)
list(APPEND EXTRA_INCLUDES ../ ./ ../../src )

target_include_directories(sniffer_all PUBLIC ${EXTRA_INCLUDES})
target_link_libraries(sniffer_all PUBLIC ${EXTRA_LIBS})

