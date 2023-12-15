#include "processor.h"
#include "formatter.h"
#include "utils.h"
#include "Log/logging.h"
#include <sstream>

namespace monitor
{
using namespace std::string_literals;

processor::~processor() {
    stop();
}

processor::processor() : internal_com{}, capture_device{default_write_channel{internal_com}} {
}

auto processor::start(config conf) -> result<bool, std::string> {
    // at this point we have the capture device ready, make sure that we can run
    if (running()) {
        return {"you cannot start the processing while it is still running, you need to stop this first"s};
    }
    consumer = std::thread([this, conf]() {
            this->run_consumer(conf);
         }
    );
    utils::rename_thread(consumer, "processor");
    const auto rc = capture_device.run({conf.interface_name.c_str(), 
        conf.filter.c_str(), 
        conf.max_memory, 
        conf.max_payload_per_msg, conf.promiscuous_mode,
        conf.port_list
    });
    if (auto e = Error(rc); e) {
        stop();
        return {std::move(e.value())};   // failed to start capture device
    }
    if (running()) {
        return ok(true);
    }
    stop();
    return failed("failed to start network capture - error starting consumer"s);
}

auto processor::counters_info::reset() -> void {
    active_sessions = 0;
    successful_sent = 0;
    completed_sessions = 0;
    failure_count = 0;
    sessions_count = 0;
    failed_sent = 0;
}

auto print_counters = [count = 0lu, success = 0lu] (auto& counters, const auto& sink) mutable {
    constexpr std::size_t DELTA = 1'000;
    std::uint64_t s = counters.sessions_count;
    if ((count % DELTA) == 0 && s != success) {
        auto remote_counters = sink.scrap_counters();
        counters.successful_sent = remote_counters.success_send;
        counters.failed_sent = remote_counters.failed_send;
        counters.completed_sessions = remote_counters.success_format;
        counters.failure_count += remote_counters.failed_format;
        LOG_HTTP_PACKETS_WARN << count << ": counters: " << counters;
        success = s;
    }
    count++;
};

auto processor::run_consumer(config conf) -> void {
    constexpr int TIMEOUT_BETWEEN_JOBS[] = {1, 5};  // see bellow
    // this function will run "forever" - or to be more exact, until stop is called
    // we will consume the packets that the capture threads is sending to us, and
    // then after formatting them, we will forward it to the consumer of this information.
    run = true;
    default_read_channel input{internal_com};
    
    std::uint16_t current_port = conf.remote_port;
    formatter message_dest{conf.remote_ports_count, conf.remote_port, conf.remote_host};

    auto process_func = [this, &conf, current_port, &message_dest](auto session) mutable{
        this->format_and_send(std::move(session), message_dest);
    };

    LOG_HTTP_PACKETS_DEBUG << "working with " << conf.remote_ports_count << " remote ports";
    
    counters.reset();
    while (run) {
        counters.active_sessions = capture_device.sessions();
        auto c = input.consume_all(process_func);
        // At this point the queue is empty, so lets give it a little rest between jobs..
        std::this_thread::sleep_for(std::chrono::milliseconds(TIMEOUT_BETWEEN_JOBS[int(c == 0)]));
        print_counters(counters, message_dest);
    }
}



auto send_failure_report = [count = 0lu](auto&& failure) mutable {
    if (((count++) % 100) == 0) {
         LOG_HTTP_PACKETS_ERR << "failed to send message: " << failure<< " for the " << count << " time";
    }
};

auto processor::format_and_send(default_channel::element_type session, formatter& target) -> void { // sink& target) -> void {
    // this function will convert the input session into a string in JSON format
    // and send it to the sink that we have to consume this message
    counters.sessions_count++;
    if (session.not_ready_size()) {
        LOG_HTTP_PACKETS_DEBUG << "got session without enough flows (" << session.downstream_size()
            <<" downstream, and upstream "<<session.upstream_size() << "), discarding";
        return;
    }
    //const auto tr = output_formatter::transform(std::move(session)); 
    //if (const auto msg = Ok(tr); msg) {
    if (!target.consume(std::move(session))) {
        counters.failure_count++;
    }
}

auto processor::stop() -> result<bool, std::string> {
    run = false;
    capture_device.stop();
    if (consumer.joinable()) {
        consumer.join();
    }
    return ok(capture_device.running());
}

auto operator << (std::ostream& os, const processor::counters_info& counters) -> std::ostream& {
    std::uint64_t as = counters.active_sessions;
    std::uint64_t cs = counters.completed_sessions;
    std::uint64_t ss = counters.successful_sent;
    std::uint64_t fc = counters.failure_count;
    std::uint64_t sc = counters.sessions_count;
    std::uint64_t fs = counters.failed_sent;

    return os << "active sessions: " << number_printer{as} << ", sessions completed: " << number_printer{cs} <<
             ", successfully sent: " << number_printer{ss} << ", failed sessions: " << number_printer{fc} <<
            ", total session seen: " << number_printer{sc} << ", failed to send: " << fs;
}

auto operator << (std::ostream& os, const processor::config& conf) -> std::ostream& {
    return os << "interface name: '" << conf.interface_name << "', filter: {" << conf.filter <<
        "}, remote host: [" << conf.remote_host << "/port: " << conf.remote_port << 
        "], connections count: " << conf.remote_ports_count << ", max allowed memory usage " << 
        float(conf.max_memory / GB2BYTES) <<" GB" << 
        " and max message size of " << (conf.max_payload_per_msg / MB2BYTES)<< " MB";
}

auto to_string(const processor::counters_info& counters) -> std::string {
    std::ostringstream s;
    s<<counters;
    return s.str();
}
auto to_string(const processor::config& conf) -> std::string {
    std::ostringstream s;
    s<<conf;
    return s.str();
}


}       // end of namespace monitor
