# The Logging System
## Overview
This will be a short guide on how to use the logging system, and how to extend it.

## Basics
### Log information
With the log we have the following information for each entry that is writing:
* Timestamp in micro seconds.
* Entry number (monotonic increase number).
* Level of the log message.
* Module name (channel).
* Source file name in which the log message was writing from.
* Line number in the source file in which it was writing.
* Thread name from in which this was running at.
* The log text itself.

### Log configuration
You can configure the log from the configureation file on the application.
The values that can be configured are:
```json
{
    "log_file_name": "monitor_log_file.log",
    "log_files_path": "/home/dbpost/logs/engine/packets_monitoring/",
    "file_max_size_mb": 10,
    "max_logs_dir_size_gb": 0.5,
    "delta_time_hours_to_delete": 5,
    "log_level": 2
  }
```
Where:
* log_file_name: The log name to which the message are writing.
* log_files_path: The location to which the log files are backup.
* file_max_size_mb: The max size for a log file (in MB).
* max_logs_dir_size_gb: The max size for the log history (in GB).
* delta_time_hours_to_delete: time to live for log files in hours (from 24).
* log_level: 1 - debug, 2 - info, 3 - warning (default), 4 - error, 5 - fatal. note that any number bigger than what you set will be printed as well. For example, if log level is set to 3, than level 4 and 5 will be writing as well.
Note about configuration:
* For agent the configuration should placed under "log_categories_settings" entry in the json configuration file.
* For analytics it should be placed under "log_categories_settings" entry in the json configuration file.
* For packet monitor it should be placed under "log_config" entry in the json configuration file.

## Using the log
### Log Levels
There exist 5 log levels:
* Debug - this is mostly for the developer who wrote the code itself, and its normally should not be enabled. Messages in this level can be very detasiled and in many location of the code. Since log level that are not enabled, are not even processed during runtime, it would not add to the runtime overhead. This is assumed to not be enabled at production.
* Info - this log level is used in placed where you have normal flow that you would like to trace, but is not as detailed and not as frequently used in the code. Again normally it not expected ot enabled in production, but may be used more in normal runs in production.
* Warning - these log messages are enable by default, and thus should not be used all over in the code. They only should be used if we have some recoverable errors happened.
* Error - This is for more sever errors, such as not getting a valid value to a function or when conneciton is lost. It is assumed that on normal runs we should not see any of those.
* Fatal - unrecoveralbe erorrs - in these cases, it should normally be just before we are about to terminate the application, and it is assumedd that it would never even happened, you can assert on these cases.

### Support for log level:
There exists macros to help with writing log messages with different level - these macro flow the pattern of <some name>_<log level>, for example:
* LOG_HTTP_PACKETS_DEBUG - this print packet monitor debug level log.
* LOG_AGENT_INFO - this print agent info log level message.
* LOG_ANALYTIC_WARN - this print analytic warning log level message.
* LOG_POLICY_ERR - this print policy error log level message.
* LOG_FOO_FATAL - this print data fuser log level message.

### Logs locations
The logs files are writing at run time to the location at which the application binary is located:
* For agent this is at "/home/l7admin/engine/agent"
* For analytics this is at "/home/l7admin/engine/analytic"
* For packet monitor this is at /home/l7admin/packets_monitoring".
After the log file is full (when the log size is at the limit of it size), the logs file is moved to "/home/dbpost/logs/engine", and a new file is created at the locations above.

## Extending logging
To create a new log channel (to have new module name in the log), you can create and add your own:
* in the file "src/Log/loggging_channels.h" add you new channel name:
Add to the enum below the new channel before "LAST_ENTRY"
For exmaple if we're creating a new channel - foo:
```cpp
enum class ChannelIndices : std::uint16_t {
    PACKET_MONITOR = 0,
    AGENT,
    ANALYTICS,
    GENERAL,
    POLICY,
    PROFILER,
    DATA_FUSER,
    ENTITY_TRACKER,
    LEARNER,
    FOO,        // our new entry here
    LAST_ENTRY  // make sure to add new ones before this one
};
```
* Add the string to
```cpp
constexpr std::string_view ALL_CHANNEL_NAMES[] = {
        "http_packets_monitor",
        "realtime-agent",
        "analytic",
        "ammune-src",
        "policy",
        "profiler",
        "data-fusing",
        "entity-tracker",
        "learner",
        "foo"       // our new entry here
};
```
in the same order as in the enum above.
Add the name as constant to the list of names:
```cpp
const std::string DEFAULT_HTTP_CHANNEL = std::string(_channel_name(ChannelIndices::PACKET_MONITOR));
const std::string DEFAULT_AGENT_CHANNEL = std::string(_channel_name(ChannelIndices::AGENT));
const std::string DEFAULT_GENERAL_CHANNEL = std::string(_channel_name(ChannelIndices::GENERAL));
const std::string DEFAULT_ANALYTIC_CHANNEL = std::string(_channel_name(ChannelIndices::ANALYTICS));
const std::string DEFAULT_POLICY_CHANNEL = std::string(_channel_name(ChannelIndices::POLICY));
const std::string DEFAULT_PROFILE_CHANNEL = std::string(_channel_name(ChannelIndices::PROFILER));
const std::string DEFAULT_DATA_FUSING_CHANNEL = std::string(_channel_name(ChannelIndices::DATA_FUSER));
const std::string DEFAULT_ENTITY_TRACKER = std::string(_channel_name(ChannelIndices::ENTITY_TRACKER));
const std::string DEFAULT_LEARNER = std::string(_channel_name(ChannelIndices::LEARNER));
const std::string DEFAULT_FOO = std::string(_channel_name(ChannelIndices::FOO));    // our new entry here
```
* Add a printing macros - so you would have it with all the information that you would inherent from the exiting macros:
in the file "src/Log/loggging_macros.h"
```cpp
#ifndef LOG_FOO
#   define LOG_FOO(level) _LOG_GENERAL_ENTRY((level), DEFAULT_DATA_FUSING_CHANNEL) 
#endif
#ifndef LOG_FOO_DEBUG
#   define LOG_FOO_DEBUG LOG_FOO(severity_level::debug) 
#endif
#ifndef LOG_FOO_INFO
#   define LOG_FOO_INFO LOG_FOO(severity_level::info) 
#endif  // LOG_FOO_INFO

#ifndef LOG_FOO_WARN
#   define LOG_FOO_WARN LOG_FOO(severity_level::warning) 
#endif  // LOG_FOO_WARN

#ifndef LOG_FOO_ERR
#   define LOG_FOO_ERR LOG_FOO(severity_level::error) 
#endif  // LOG_FOO_ERR

#ifndef LOG_FOO_FATAL
#   define LOG_FOO_FATAL LOG_FOO(severity_level::critical) 
#endif  // LOG_FOO_FATAL
```
And this is it, the new channel is ready to use.

### In the code
To add new log message with our new channel:
* inclue the file "Log/logging.h" in the file in which you like to print the message to.
* Use it just as you are using normal C++ streams:
```cpp
if (something_not_working) {
    LOG_FOO_ERR << "we have some error with the code that is not working: we have have these parameters: x = " << x << ", y = " << y << " and z = " << z;
}
```
Please note that if the type you want to write to the log is not support the "<<" operator yet, then please add this operator to this type:
```cpp
struct MyType {
    int a;
    int b;
    double d;
    std::string s;
};

auto operator << (std::ostream& os, const MyType& t) -> std::ostream& {
    return os << "a = " << t.a << ", b = " << t.b << ", d = " << t.d << ", s = " << std::quated(t.s);
}
```
And now this type is ready to use with the log.