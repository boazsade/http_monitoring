#include "logging_channels.h"
#include "logging.h"
#include "text_color.h"
#include <boost/log/expressions.hpp>
#include <boost/log/sources/severity_channel_logger.hpp>
#include <boost/log/sources/record_ostream.hpp>
#include <boost/log/utility/setup/console.hpp>
#include <boost/log/utility/setup/common_attributes.hpp>
#include <boost/log/utility/setup/file.hpp>
#include <boost/log/sinks.hpp>
#include <boost/log/support/date_time.hpp>
#include <iostream>
#include <iomanip>

namespace
{
constexpr auto get_severity = [] (std::size_t sev) -> severity_level {
        constexpr severity_level converter[] = {
            severity_level::info,
            severity_level::debug,
            severity_level::info,
            severity_level::warning,
            severity_level::error,
            severity_level::critical
        };
        return sev < std::size(converter) ? converter[sev] : severity_level::info;
};

}   // end of local namespace

namespace expr = boost::log::expressions;
namespace keywords = boost::log::keywords;
namespace sinks = boost::log::sinks;

// Define the attribute keywords
BOOST_LOG_ATTRIBUTE_KEYWORD(line_id, "LineID", unsigned int)
BOOST_LOG_ATTRIBUTE_KEYWORD(severity, "Severity", severity_level)
BOOST_LOG_ATTRIBUTE_KEYWORD(channel, "Channel", std::string)

auto operator<< (std::ostream& strm, severity_level level) -> std::ostream& {
    static const char* strings[] =
    {
        "NONE", // we start with 1 so this is just a place holder
        "DEBUG",
        "INFO",
        "WARNING",
        "ERROR",
        "CRITICAL"
    };
    auto index = static_cast< std::size_t >(level);
    if (index < std::size(strings)) {
        strm << strings[index];
    } else {
        strm << "??";
    }

    return strm;
}

using min_severity_filter = expr::channel_severity_filter_actor< std::string, severity_level >;

auto set_log_severity(logger_filters&& channels) -> void {
    min_severity_filter min_severity = expr::channel_severity_filter(channel, severity);

    // Set up the minimum severity levels for different channels
    for (auto c : channels) {
        min_severity[c.first] = c.second;
    }
    boost::log::core::get()->set_filter(min_severity);
}

auto init_logger(const std::string& dir, const std::string file, std::uint32_t size, logger_filters&& channels, std::uint32_t rotate_at) -> bool {
    std::cout << GREEN <<  "starting log for directory "  << std::quoted(dir) << " at file " << std::quoted(file) << ", with size " << size << std::endl;
    // Create a minimal severity table filter
    constexpr auto MAX_ROTATE_TIME = 23;
    constexpr auto MEGABYTES_FACTOR = 1024 * 1024;
    
    rotate_at = rotate_at > MAX_ROTATE_TIME ? MAX_ROTATE_TIME : rotate_at;

    try {
        min_severity_filter min_severity = expr::channel_severity_filter(channel, severity);

        // Set up the minimum severity levels for different channels
        for (auto c : channels) {
            std::cout << "setting log severity for channel " << c.first << std::endl;
            min_severity[c.first] = c.second;
        }
        set_log_severity(std::move(channels));
        logging::add_file_log
        (
            keywords::target_file_name = dir + "/rotate-%N-" + file,
            keywords::target = dir,
            keywords::min_free_space = 1900 * MEGABYTES_FACTOR,  // don't use all free space on the disk!
            keywords::max_files = 10,   // limit the number of files that we are saving
            keywords::file_name = file,
            keywords::rotation_size = size * MEGABYTES_FACTOR,
            keywords::time_based_rotation = sinks::file::rotation_at_time_point(rotate_at, 0, 0),
            keywords::filter = min_severity || severity >= severity_level::critical,
            keywords::auto_flush = true,
            keywords::format =
            (
                expr::stream << std::left <<"["<<std::setw(8)<<std::setfill(' ')<<
                    expr::format_date_time< boost::posix_time::ptime >("TimeStamp", "%Y-%m-%d %H:%M:%S.%f")
                    << "|"<<std::setw(8)<<std::setfill(' ')<<line_id << "|"<<std::setw(12)<<std::setfill(' ') << severity 
                    << "|" << std::setw(20)<<std::setfill(' ')<< channel << "]: " << "|: "
                    << expr::smessage
            )
        );

        logging::add_common_attributes();
        std::cout << GREEN << "successfully finish setup the log" << std::endl;
        return true;
    } catch (const std::exception& e) {
        std::cerr << RED << "failed to build logger: "<<e.what() << RESET << std::endl;
        return false;
    }
}

auto init_logger_default(const std::string& dir, const std::string file, 
        std::uint32_t size, std::uint32_t rotate_at, severity_level filter) -> bool {
    auto make_filter = [filter] () {
        logger_filters res;
        for (auto f : ALL_CHANNEL_NAMES) {
            res.emplace_back(std::string(f), filter);
        }
        return res;
    };

    return init_logger(dir, file, size, make_filter(), rotate_at);
}

auto make_log_severity(std::size_t level) -> filter_type::second_type {
    return get_severity(level);
}

auto bytes_formatter::operator () () const -> std::string {
    constexpr std::string_view suffix[] = {"B", "KB", "MB", "GB", "TB"};
    constexpr std::size_t factor = 1'024;
    constexpr std::size_t length = std::size(suffix);
    auto cp = value;
    double dblBytes = value;

    auto i = 0lu;
    if (cp > factor) {
        for (; (cp / factor) > 0 && i < length - 1; i++, cp /= factor)
            dblBytes = cp / double(factor);
    }

    std::ostringstream s;
    s << std::setw(2) << std::setfill('0') << std::fixed << std::setprecision(3) << dblBytes << " " << suffix[i];
    return s.str();
}
