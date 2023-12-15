#pragma once
#include <boost/log/sources/record_ostream.hpp>
#include <boost/log/sources/severity_logger.hpp>
#include <boost/log/sources/severity_channel_logger.hpp>
#include <boost/log/sources/global_logger_storage.hpp>
#include <string>
#include <vector>
#include <utility>
#include <iostream>
#include <iomanip>
#include <thread>

enum class severity_level : std::size_t {
    debug = 1,
    info = 2,
    warning = 3,
    error = 4,
    critical = 5
};

namespace logging = boost::log;
namespace src = boost::log::sources;
using logger_type_t = src::severity_channel_logger_mt<severity_level, std::string>;
using filter_type = std::pair<std::string, severity_level>;
using logger_filters = std::vector<filter_type>;
