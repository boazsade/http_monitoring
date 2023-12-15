#pragma once
#include "logging_channels.h"
#include <thread>
#include <pthread.h>
#include <string>

namespace _internal
{

inline auto _thread_name_() -> std::string {
    using namespace std::string_literals;

    auto self = pthread_self();
    char name[64];
    if (pthread_getname_np(self, name, 64) == 0) {
        return std::string{name};
    } else {
        return "unknown-id"s;
    }
}

}   // end of namepace _internal


#define __FILENAME__ (__builtin_strrchr(__FILE__, '/') ? __builtin_strrchr(__FILE__, '/') + 1 : __FILE__)

#ifndef _LOG_GENERAL_ENTRY
#   define _LOG_GENERAL_ENTRY(level, channel) BOOST_LOG_STREAM_CHANNEL_SEV(logger_handle(), (channel), (level))  << ": " << __FILENAME__ << "@" << __LINE__ <<": "<<"| thread: " << _internal::_thread_name_() <<": "
#endif // _LOG_GENERAL_ENTRY

#ifndef LOG_HTTP_PACKETS
#   define LOG_HTTP_PACKETS(level) _LOG_GENERAL_ENTRY((level), DEFAULT_HTTP_CHANNEL)
#endif  // LOG_HTTP_PACKETS

#ifndef LOG_HTTP_PACKETS_DEBUG
#   define LOG_HTTP_PACKETS_DEBUG LOG_HTTP_PACKETS(severity_level::debug)
#endif  // LOG_HTTP_PACKETS_DEBUG

#ifndef LOG_HTTP_PACKETS_INFO
#   define LOG_HTTP_PACKETS_INFO  LOG_HTTP_PACKETS(severity_level::info)
#endif  // LOG_HTTP_PACKETS_INFO

#ifndef LOG_HTTP_PACKETS_WARN
#   define LOG_HTTP_PACKETS_WARN  LOG_HTTP_PACKETS(severity_level::warning)
#endif  // LOG_HTTP_PACKETS_WARN

#ifndef LOG_HTTP_PACKETS_ERR
#   define LOG_HTTP_PACKETS_ERR  LOG_HTTP_PACKETS(severity_level::error)
#endif  // LOG_HTTP_PACKETS_ERR

#ifndef LOG_HTTP_PACKETS_FATAL
#   define LOG_HTTP_PACKETS_FATAL LOG_HTTP_PACKETS(severity_level::critical)
#endif  // LOG_HTTP_PACKETS_FATAL

