// run application for monitoring packets over network
#include "http_monitor/processor.h"
#include "http_monitor/capture.h"
#include "http_monitor/results.h"
#include "http_monitor/channel.h"
#include "http_monitor/results.h"
#include "Log/text_color.h"
#include "Log/logging.h"
#include <boost/stacktrace.hpp>
#include <boost/program_options.hpp>
#include <thread>
#include <csignal>
#include <iostream>
#include <fstream>
#include <numeric>
#include <sstream>
#include <chrono>

using namespace std::string_literals;

namespace
{

struct log_config {
    std::uint64_t file_max_size_mb = 100;
    std::size_t log_level = 3;  // warning
    std::string log_files_path = "/var/log";
    std::string log_file_name = "demo_http_capture.log";
    std::uint32_t delta_time_hours_to_delete = 6;
};


struct configuration {
    log_config log;
    monitor::processor::config general_conf;
};



namespace po = boost::program_options;

constexpr float DEFAULT_MAX_MEM_GB = 4;                 // GB
constexpr std::uint32_t DEFAULT_SESSION_SIZE_MB = 1;    // MB


auto setup_log(const log_config& conf) -> bool {
    auto max_size = safe_max_log_size(conf.file_max_size_mb);
    auto severity = make_log_severity(conf.log_level);
    if (init_logger(conf.log_files_path, conf.log_file_name, max_size, 
        {{DEFAULT_HTTP_CHANNEL, severity}},
        conf.delta_time_hours_to_delete)) {
        return true;
    } else {
        std::cerr<<"failed to setup log"<<std::endl;
        return false;
    }
}

auto atexit_setup() -> void {
    const auto closed_handler = [] (int signal_num) -> void {
            auto buf = std::array<char, 8192>{};
            const auto size = boost::stacktrace::safe_dump_to(buf.data(), buf.size());
            const auto st = boost::stacktrace::stacktrace::from_dump(buf.data(), buf.size());
            std::cerr << RED << "exit as result of signal "<<signal_num<<"\nbacktrace:\nfrom dump (" << size << " frames):\n" << st << std::endl
                << "backtrace symbols:\n" << RESET << boost::stacktrace::stacktrace{} << std::endl;
            LOG_HTTP_PACKETS_WARN << "going out as result of signal " << signal_num;
            LOG_HTTP_PACKETS_WARN << "exit as result of signal "<< signal_num << "\nbacktrace:\nfrom dump (" << size << " frames):\n" << st << std::endl
                << "backtrace symbols:\n" << boost::stacktrace::stacktrace{};

        exit(1);
    };

    const int signals[] = {
            SIGSEGV, 
            SIGFPE, 
            SIGABRT,
            SIGILL,
            SIGHUP, 
            SIGTERM,
            SIGINT, 
            SIGQUIT, 
            SIGTSTP,
            SIGPIPE,
            SIGKILL
    };
    // add signal handler for the list of signals above
    for (auto s : signals) {
        signal(s, closed_handler);
    }
}



auto setup_config(const configuration& conf) -> result<bool, std::string> {

    setup_log(conf.log);

    if (auto e = Error(monitor::validate_interface(conf.general_conf.interface_name.c_str())); e) {
        return  failed(e.value());
    }

    if (auto e = Error(monitor::validate_filter(conf.general_conf.filter.c_str(), conf.general_conf.interface_name.c_str())); e) {
        return failed(e.value());
    }
    return ok(true);

}


auto print_session = [](const auto& sessions) -> void {
    int i = 0;
    for (const auto& s : sessions) {
        std::cout << "[" << i++ << "]: " << s.second << "\n------------------------------------------------------\n";
        if (i > 10) {
            break;
        }
    }
    std::cout << std::endl;
};

auto run_monitor(const monitor::processor::config& conf, std::size_t max) -> int {
    using namespace monitor;
    using channel_type = default_channel;

    channel_type comm;
    network_capture capture_dev{default_write_channel{comm}};
    std::size_t counter = 0;
    std::size_t failed_count = 0;
    
    LOG_HTTP_PACKETS_WARN << "starting capture on device " << conf.interface_name << " and filter " << conf.filter  
        << " with promiscuous mode " << std::boolalpha << conf.promiscuous_mode;
    auto r = capture_dev.run({
        conf.interface_name.c_str(), conf.filter.c_str(), DEFAULT_MAX_MEMORY, DEFAULT_MAX_MESSAGE, conf.promiscuous_mode, {}
    });
    if (r.is_error()) {
        LOG_HTTP_PACKETS_FATAL << "failed to start capture device!! " << r;
        return -1;
    }
    default_read_channel input{comm};
    while (counter < max) {
        auto i = input.consume_all([&counter, &failed_count](auto&& session) mutable {
            if (session.not_ready_size()) {
                failed_count++;
            } else {
                ++counter;      // count how many we successfully read
            }
        });
        if (i == 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        if ((counter % 100) == 0 && i > 0) {
            LOG_HTTP_PACKETS_WARN << "we captured " << number_printer<std::size_t>(counter) << " flows so far and we've have  " << capture_dev.sessions() << " open sessions";
        }
        if (capture_dev.sessions() > 200) {
            print_session(capture_dev.live_sessions());
            break;
        }
    }

    capture_dev.stop();
    LOG_HTTP_PACKETS_WARN << "we successfully captured " << counter << ", and we had " << failed_count << " invalid http flows from device " 
        << conf.interface_name << " and filter " << conf.filter  << " with promiscuous mode " << std::boolalpha << conf.promiscuous_mode;
    return 0;
}

auto process_cli(int ac, char** av) -> result<configuration, int> {

    try {
        po::options_description desc("CLI options for http capture");
        log_config lc;
        std::string interface;
        std::string filter;
        std::uint16_t threads = 4;
        std::uint64_t max_msg = 10 * 1'024 * 1'024;
        std::string host{"localhost"};
        desc.add_options()
            ("help,h", "produce help message")
            ("filter.f", po::value<std::string>(&filter)->required(), "set the capture filter - in the form of host port, for example: host 1.1.1.1 and port 1234")
            ("log-level,l", po::value<std::size_t>(&lc.log_level), "set log level for this program (choose 1 to 5, default 3 (warning), were 1 is debug and 5 is fatal)")
            ("log-name,n", po::value<std::string>(&lc.log_file_name), "set log file name for this program (default to [demo_http_capture.log])")
            ("interface,i", po::value<std::string>(&interface)->required(), "the name of the interface that we are capturing on)")
            ("max-msg,m", po::value<std::uint64_t>(&max_msg), "the size of memory that we are allowing for a given message (in bytes- default 10MB")
            ("writers,w", po::value<std::uint16_t>(&threads), "number of threads to process with - default 4")
            ("host,r", po::value<std::string>(&host), "host to send results to - default localhost")
            ("log-path,p", po::value<std::string>(&lc.log_files_path), "set log directory for this program (default to [/var/log])");

        po::variables_map vm;
        po::store(po::parse_command_line(ac, av, desc), vm);

        
        po::notify(vm);

        if (vm.count("help")) {
            std::cout << desc << "\n";
            return failed(0);
        }

        if (lc.log_level > std::uint32_t(severity_level::critical)) {
             std::cerr <<  "invalid log level: must be between " << std::uint32_t(severity_level::debug) <<  " and "  << std::uint32_t(severity_level::critical);
            return failed(1);
        }
        return ok(configuration {
            lc, 
            monitor::processor::config {
                interface, filter, monitor::processor::DEFAULT_TARGET_PORT, threads, host
            }
        });

    } catch(const std::exception& e) {
        std::cerr << "error: " << e.what() << "\n";
        return failed(1);
    } catch(...) {
        std::cerr << "Exception of unknown type!\n";
        return failed(1);
    }
    return failed(0);
}

}       // end of local namespace

// This function will:
//  1. setup exit handler for the signals
//  2. read configuration from a file
//  3. setup the log
//  4. setup the capture configuration value
//  6. start the capture device and run.
auto main(int argc, char** argv) -> int {
    std::size_t max = 1'000'0000;
    if (argc > 1) {
        max = std::atoll(argv[1]);
    }
    atexit_setup();
    const auto conf = process_cli(argc, argv);
    if (!conf) {
        std::cerr << "error processing command line\n";
        return -1;
    }
    const auto configuration = conf.unwrap();
    const auto conf_res = setup_config(configuration);
    if (auto c = Ok(conf_res); c) {
        return run_monitor(configuration.general_conf, max);
    }
    std::cerr << "Error: Found invalid configuration.\n" << conf_res.error_value() << "\nExiting.\n";
    return -1;
    
}
