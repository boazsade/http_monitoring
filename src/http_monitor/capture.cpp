#include "capture.h"
#include "results.h"
#include "utils.h"
#include "Log/logging.h"
#include <pcap.h>
#include <vector>
#include <string>
#include <algorithm>
#include <cstring>
#include <iostream>
#include <numeric>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <iostream>

namespace monitor
{

using namespace std::string_literals;

namespace
{

struct issues_reports {
    std::size_t count = 0;
    const std::string_view message;

    explicit issues_reports(const std::string_view m) : count{0}, message{m} {

    }

    auto operator () () -> void {
        count++;
        if ((count % 1'000) == 0) {
            LOG_HTTP_PACKETS_WARN << "seen " << count << " time for " << message;
        }
    }
};


auto gc_monitoring = [count = 0lu](auto before, auto after) mutable {
    if (before > after) {
        count += (before - after);
        if ((count % 1'000) == 0) {
            LOG_HTTP_PACKETS_INFO << "successfully removed " << count << " entries by the GC because they are no longer in use";
        }
    }
};


auto count_to_small = [counter = issues_reports{" packet that were dropped because they are too small"}]() mutable {
    counter();
};

auto count_invalid_len = [counter = issues_reports{" packet that were dropped because they are with invalid length"}]() mutable -> void {
    counter();
};

auto count_invalid_type = [counter = issues_reports{" packet that were dropped because they where with invalid type (not IPv4)"}]() mutable -> void {
    counter();
};


 auto report_memory_usage = [lt = time(nullptr)](auto c, const auto& f, const auto& new_flow, auto max_allow_mem) mutable {
        auto ct = time(nullptr);
        if (ct > lt + 600) { // report only if we didn't do it for the last 10 minute
            LOG_HTTP_PACKETS_WARN << "cannot save packet " << new_flow << ", the total allow memory usage limit " << 
                max_allow_mem << " and we are already at " << c << " which only leave room for " << 
                int(max_allow_mem - c) << " bytes";
            LOG_HTTP_PACKETS_WARN << "we are using " << c << " bytes of memory, we have " << f.saved() << " sessions in memory";
            lt = ct;
        }
};

auto report_not_send = [count = 0lu](bool success) mutable {
    if (!success) {
        count++;
        if ((count % 10'000) == 0) {
            LOG_HTTP_PACKETS_WARN << "failed to send session for processing for the " << number_printer{count} << " time (sessions dropped)";
        }
    }
};

auto count_not_sent = [count = 0lu] (auto&& what) mutable {
    count++;
    if ((count % 10'000) == 0) {
        LOG_HTTP_PACKETS_WARN << "we are dropping " << number_printer<std::uint64_t>{count} << " packets because of " << (what.is_encrypted() ? "TLS packet" : "empty");
    }
};

auto count_success = [count = 0lu, bytes = 0lu](std::uint32_t b) mutable {
    count++;
    bytes += b;
    if ((count % 1'000'000) == 0) {
        LOG_HTTP_PACKETS_WARN << "we successfully processed " << number_printer<std::uint64_t>{count} << " packets so far, (" << bytes_formatter{bytes} << ")";
    }
};

auto start_promiscuous(const char* dev_name, int cap_len, int timeout) -> result<pcap_t*, std::string> {
    constexpr int MAX_BUFFER = 1024 * 1024 * 1024;
    // this is for promiscuous mode, which is different than normal start
    if (dev_name == ANY_DEVICE) {
        return failed("cannot open ANY device for capture in promiscuous mode"s);
    }
    char ebuf[PCAP_ERRBUF_SIZE];
    auto ph = pcap_create(dev_name, ebuf);
    if (!ph) {
        return failed("failed to open device "s + dev_name + " for capture: "s  + ebuf);
    }
    if(pcap_set_promisc(ph, 1) == 0) {
        pcap_set_buffer_size(ph, MAX_BUFFER);
        pcap_set_snaplen(ph, cap_len);
        pcap_set_timeout(ph, timeout);
        if (pcap_activate(ph) != 0) {
            return failed("failed to start capture on device "s + dev_name + " in promiscuous mode");
        }
    } else {
        return failed("failed to set device "s + dev_name + " into promiscuous mode"s);
    }
    LOG_HTTP_PACKETS_WARN << "device " << dev_name << " started successfully in promiscuous mode";
    return ok(ph);
}

auto print_pcap_stats = [count = 0lu](pcap_t* handle) mutable {
    ++count;
    if ((count % 1'000'000) == 0 && handle) {
        pcap_stat s;
        if (pcap_stats(handle, &s) == 0) {
            LOG_HTTP_PACKETS_WARN << "pcap stats: dropped: " << bytes_formatter(s.ps_drop) << ", captured: " << bytes_formatter(s.ps_recv) << ", dropped by interface: " << bytes_formatter(s.ps_ifdrop);
        }
    }
};


constexpr auto time_str = [](auto timestamp) -> std::string {
    constexpr time_t SECONDS2MICROS = 1'000'000; 
    char tmp_buf[64];
    time_t now_time = timestamp / SECONDS2MICROS;
    auto micros = timestamp % SECONDS2MICROS;
    auto now_tm = localtime(&now_time);
    strftime(tmp_buf, sizeof tmp_buf, "%Y-%m-%d %H:%M:%S", now_tm);
    return std::string(tmp_buf) + "." + std::to_string(micros);
};

auto start_normal_capture(const char* dev_name, int cap_len, int timeout) -> result<pcap_t*, std::string> {
    LOG_HTTP_PACKETS_INFO << "starting the device " << dev_name << " without support for promiscuous mode";
	char ebuf[PCAP_ERRBUF_SIZE];
	auto ph = pcap_open_live(dev_name, cap_len, 1, timeout, ebuf);
	if (!ph) {
		return {"failed to open live capture from device "s + dev_name + ebuf};
	}
	return {std::move(ph)};
}

auto list_interfaces() -> result<std::vector<std::string>, std::string> {
	pcap_if_t* info = nullptr;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	if (pcap_findalldevs(&info, errbuf) < 0) {
		return {"failed to open device list: "s + errbuf};
	}
	auto currInterface = info;
    std::vector<std::string> interfaces_list;
	while (currInterface != nullptr) {
        interfaces_list.emplace_back(currInterface->name);
		currInterface = currInterface->next;
	}

	pcap_freealldevs(info);
    return {std::move(interfaces_list)};
}

auto packet_handler(std::uint8_t *args, const struct pcap_pkthdr* header, const std::uint8_t* packet) -> void {

    auto monitor = (network_capture::monitor_handler::network_device *)args;
    if (!monitor) {
        throw std::runtime_error("post condition error: missing capture handler for saving packet results");
    }

    print_pcap_stats(monitor->handle());
    const auto ret = monitor->process(header, packet);
    if (auto loc = Ok(ret); loc) {      
        count_success(header->caplen);
        //monitor->send_ready(loc.value());      // in case we have any packet that is ready to be sent do it here
        monitor->count_success();
    } else {
        monitor->count_drop();
    }
}

}   // end of local namespace

auto validate_interface(interface_id device_name) -> result<bool, std::string> {
    if (device_name == ANY_DEVICE) {
        return ok(true);    // we don't need to really validate this
    }
    const auto if_list = list_interfaces();
    if (const auto interfaces = Ok(if_list); interfaces) {
        auto ifl = interfaces.value();
        if (std::find(std::begin(ifl), std::end(ifl), device_name) == std::end(ifl)) {
            std::string all_interface = std::accumulate(std::begin(ifl), std::end(ifl), std::string{},  [] (auto&& cr, auto&& i) {
                return cr + "\n" + i;
            });
           return failed("Invalid interface name: "s + device_name + ". Not found in this host, valid devices are:\n" + all_interface);
        }
        return ok(true);
    }
    return failed(std::string(if_list.error_value()));
}

auto validate_filter(filter_type filter, interface_id device_name) -> result<bool, std::string> {
    std::string if_name;
    // try to find a valid device to test on
    if (!device_name) {
        const auto interfaces_res = list_interfaces();
        if (const auto interfaces = Ok(interfaces_res); interfaces) {
            // we cannot really capture..
            auto if_list = interfaces.value();
            if (if_list.empty()) {
                return {std::string{"no network interface found"}};
            }
            if_name = if_list[0];
        } else {
            return {std::string(interfaces_res.error_value())};
        }
    } else {
        if_name = device_name;
    }

    const auto ph_r = start_normal_capture(if_name.c_str(), 1, 0);    // we don't really care about this..
    if (const auto ph = Ok(ph_r); ph) {
        struct bpf_program fp;
        auto ret = pcap_compile(ph.value(), &fp, filter, 0, PCAP_NETMASK_UNKNOWN);
        if (ret != 0) {
            std::string err = pcap_geterr(ph.value());
            pcap_close(ph.value());
            return failed("invalid filter: '"s + filter + "': failed to compile or set filter values: "s + err);
        }
        pcap_close(ph.value());
        return ok(true);
    } else {
        return failed(std::string(ph_r.error_value()));
    }
    return ok(true);
}

auto network_capture::monitor_handler::start(pcap_t* ph, std::uint64_t max_memory, std::uint64_t max_msg,
                        std::string_view dev, const std::vector<std::uint16_t>& ports) -> void {
    stop();
    mem_counters.start(max_memory);
    networking_task.startup(ph, dev);
    sessions_task.startup(max_msg, ports);
}

auto network_capture::stop() -> bool {
    if (running()) {
        LOG_HTTP_PACKETS_WARN << "capture device is being stopped";
        monitor.stop();
        // if (worker.joinable()) {
        //     worker.join();  // sync with the background thread
        // }
        LOG_HTTP_PACKETS_WARN << "capture device successfully stopped";
    }
    return running();
}

auto network_capture::run(config conf) -> result<bool, std::string> {
    if (running()) {    // invalid call, stop it first
        return {"trying to run live capture while other session in in progress"s};
    }

	const auto ph_res = conf.promiscuous_mode ? start_promiscuous(conf.device, conf.capture_size, conf.timeout) : 
        start_normal_capture(conf.device, conf.capture_size, conf.timeout);
    if (auto ph = Ok(ph_res); ph && ph.value()) {
        auto pcap_handle = ph.value();
        try {
		    struct bpf_program fp;
		    if (pcap_compile(pcap_handle, &fp, conf.filter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
                monitor.stop();
                return failed("failed to compile filter for live capture"s);
		    }
		    if (pcap_setfilter(pcap_handle, &fp) == -1) {
                monitor.stop();
			    return failed("failed to open device for capture - set filter failed"s);
		    }
            monitor.start(pcap_handle, conf.max_memory, conf.max_session_payload, conf.device, conf.ports);
            
        } catch (const std::exception& e) {
            monitor.stop();
            return failed("error while running live capture from "s + conf.device + ", with filter " + conf.filter + ": " + e.what());
        }
    } else {
        return failed(std::string{ph_res.error_value()});   // assume this will not happen many times..
    }
    return ok(true);


}


///////////////////////////////////////////////////////////////////////////////////////////

auto network_capture::monitor_handler::network_device::stop() -> bool {
    if (running()) {
        work = false;
        if (pcap_handler) {
            pcap_breakloop(pcap_handler);
            pcap_close(pcap_handler);
        }
        if (worker.joinable()) {
            worker.join();
        }
    }
    return running();
}

auto network_capture::monitor_handler::network_device::setup(pcap* ph, std::string_view dev) -> bool {
    if (ph) {
        pcap_handler = ph;
        ether_offset = ethernet_header_expected_len(dev);
        return true;
    }
    return false;
}

auto network_capture::monitor_handler::network_device::startup(pcap* ph, std::string_view dev) -> bool {
    if (setup(ph, dev)) {
        run();
        return true;
    }
    return false;
}

auto network_capture::monitor_handler::network_device::run() -> void {
    work = true;
    worker = std::thread([this] () {
        this->capture();
    });
    utils::rename_thread(worker, "capture-task");
}

auto network_capture::monitor_handler::network_device::capture() -> bool {
    constexpr int RUN_INDEFINITE = 0;
	pcap_loop(pcap_handler, RUN_INDEFINITE, packet_handler, (std::uint8_t*)this);
    return true;
}

auto network_capture::monitor_handler::network_device::try_from(const struct pcap_pkthdr* header, const std::uint8_t* packet) const -> result<internal_channel::element_type, std::string> {
    auto cap_res = from_capture(header, packet, ether_offset);
    if (cap_res) {
        return {std::move(cap_res.value())};
    }
    
    return failed("failed to convert packet size " + std::to_string(header->caplen) + " into valid flow");
}

auto network_capture::monitor_handler::network_device::parse(const std::uint8_t* packet, const struct pcap_pkthdr* header) -> result<bool, std::string> {
    const auto r = try_from(header, packet);
    if (r) {
        return ok(output_channel.send(std::move(r.unwrap())));
    }
    
    return ok(false);   // this is just error that can be ignored
}

auto network_capture::monitor_handler::network_device::process_it(const struct pcap_pkthdr* header, const std::uint8_t* packet) -> result<bool, std::string> {
    if (header->caplen < ether_offset) {
        count_to_small();
        return {"illegal packet len "s + std::to_string(header->caplen) + ", less than " + std::to_string(ether_offset)};
    }
    if (header->len > header->caplen) {
        count_invalid_len();
        return {"illegal packet length for len "s + std::to_string(header->len)  + " larger than " + std::to_string(header->caplen)};
    }
    return parse(packet, header);
}

auto network_capture::monitor_handler::network_device::process(const struct pcap_pkthdr* header, const std::uint8_t* packet) -> result<bool, std::string> {
    constexpr std::ptrdiff_t VLAN_OFF = 4;

    if (header->caplen < ether_offset) {
        count_to_small();
        return {"illegal packet len "s + std::to_string(header->caplen) + ", less than " + std::to_string(ether_offset)};
    }
    if (header->len > header->caplen) {
        count_invalid_len();
        return {"illegal packet length for len "s + std::to_string(header->len)  + " larger than " + std::to_string(header->caplen)};
    }
#ifndef ENABLE_VLAN_UT
    if (!work) {    // don't continue with the capture
        pcap_breakloop(pcap_handler);
        return ok(false);           // just ignore
    }
#endif      // ENABLE_VLAN_UT    
    //run_gc();   // we need to cleanup any sessions that are living for to long
    auto type = type_from_capture({packet, header->caplen}, ether_offset);
    switch (type) {
        case ethernet_type::ETHER_IPv4:
            return process_it(header, packet);
        case ethernet_type::ETHER_VLAN:
            {
                packet += VLAN_OFF;
                pcap_pkthdr new_header;
                new_header.ts = header->ts;
                new_header.caplen = std::uint32_t(header->caplen - VLAN_OFF);
                new_header.len = std::uint32_t(header->len - VLAN_OFF);
                return process_it(header, packet);
            }
        default:
            count_invalid_type();
            return ok(false);   // no error, but not successful either
    }
    return ok(false);           // no error, but not successful either
}

///////////////////////////////////////////////////////////////////////////////

auto network_capture::monitor_handler::memory_usage::start(std::uint64_t max_mem) -> void {
    total_memory_usage = 0;
    max_allow_mem = max_mem;
}

///////////////////////////////////////////////////////////////////////////////

auto network_capture::monitor_handler::sessions_device::run_gc() -> void {
    // go over all the sessions, any session that live to long
    // and still in the list, please remove it
    constexpr std::uint64_t MAX_TIME_TO_LIVE_USEC = 60lu * 1'000lu* 1'000lu;   // 1 minutes
    std::uint64_t current_time = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now().time_since_epoch()).count();
    auto prev_sessions = live_flows.sessions.size();
    const auto time2live = current_time - MAX_TIME_TO_LIVE_USEC;
    
    for (auto it = live_flows.begin(); it != live_flows.end();) {
        auto& session = it->second;
        if (!session.empty() && session.lifetime() < time2live) {
            session.marked_partial();
            send_session(session.take());
            it = live_flows.sessions.erase(it);
        } else {
            ++it;
        }
    }
    if (live_flows.saved() != prev_sessions) {
        gc_monitoring(prev_sessions, live_flows.sessions.size());
    }

}

auto network_capture::monitor_handler::sessions_device::free_space() -> void {
    // we would like to remove any encrypted session since we dont have much to do with it anyways
    auto size_removed = 0lu;
    
    for (auto i = live_flows.begin(); i != live_flows.end(); ) {
        if (i->second.is_encrypted()) {
            size_removed += i->second.payloads_memory();
            i = live_flows.sessions.erase(i);
        } else {
            ++i;
        }
    }
    (*mem_counters) -= size_removed;

    run_gc();   // try to remove anything that is "old enough"
    
}

auto network_capture::monitor_handler::sessions_device::send_ready(session_iter last_processed) -> void {
    if (last_processed == live_flows.end()) {
        return;
    }
    bool is_done = last_processed->second.done();
    if (auto output = take_if(last_processed->second); output) {
        send_session(std::move(*output));
        if (is_done) {
            live_flows.sessions.erase(last_processed);
        }
    }
}

auto network_capture::monitor_handler::sessions_device::send_session(session_payload&& expired) -> void {
    (*mem_counters) -= expired.payloads_memory();    // remove this from the memory usage
    if (expired.is_encrypted() || expired.empty()) {
        count_not_sent(expired);
        return;
    }
    report_not_send(write_channel.send(std::move(expired)));
}

auto network_capture::monitor_handler::sessions_device::run() -> void {
    stop();
    worker = std::thread([this]() {
        this->do_work();
    });
    utils::rename_thread(worker, "sessions-task");
}

auto network_capture::monitor_handler::sessions_device::setup(std::uint64_t max_msg, const std::vector<std::uint16_t>& p) -> void {
    ports = p;
    live_flows.set_rate_limit(max_msg);
}

auto network_capture::monitor_handler::sessions_device::stop() -> bool {
    if (!running()) {
        work = false;
        if (worker.joinable()) {
            worker.join();
        }
    }
    return running();
}

auto network_capture::monitor_handler::sessions_device::startup(std::uint64_t max_msg, const std::vector<std::uint16_t>& p) -> bool {    
    setup(max_msg, p);
    run();
    return true;
}

auto network_capture::monitor_handler::sessions_device::do_work() -> void {    
    static constexpr auto no_work_timeout = std::chrono::milliseconds(5);

    work = true;

    while (work) {
        auto c = input_channel.consume_all([this](auto&& session) {
            auto it = this->process(std::move(session));
            this->send_ready(it);
        });
        if (c == 0) {
            std::this_thread::sleep_for(no_work_timeout);
        }
    }
}

auto network_capture::monitor_handler::sessions_device::process(internal_channel::element_type flow) -> session_iter {
    if (mem_counters->will_overflow(flow.payload_size())) {
        report_memory_usage(mem_counters->mem_usage(), live_flows, flow, mem_counters->threshold());
        free_space();
    }

    auto new_mem = flow.payload_size(); 
    auto it = live_flows.add_flow(std::move(flow));
    if (it != live_flows.end()) {
        (*mem_counters) += new_mem;
    }
    return it;
}

auto operator << (std::ostream& os, const network_capture::monitor_handler::memory_usage& mem) -> std::ostream& {
    return os << "used memory: " << bytes_formatter(mem.mem_usage());
}

}   // end of namespace monitor
