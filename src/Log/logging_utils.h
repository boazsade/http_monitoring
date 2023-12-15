#include "logging_defs.h"
#include <type_traits>

constexpr std::uint32_t DEFAULT_LOG_SIZE = 1'024 * 1'024 * 100; 

BOOST_LOG_INLINE_GLOBAL_LOGGER_DEFAULT(global_logger, logger_type_t)

auto set_log_severity(logger_filters&& channels) -> void;

auto make_log_severity(std::size_t level) -> filter_type::second_type;

constexpr inline auto safe_max_log_size(std::uint64_t from) -> std::uint32_t {
    return from > DEFAULT_LOG_SIZE ? DEFAULT_LOG_SIZE : static_cast<std::uint32_t>(from);
}

auto init_logger(const std::string& dir, const std::string file, std::uint32_t size, 
    logger_filters&& channels, std::uint32_t rotate_at) -> bool;

// init all the channels we have
auto init_logger_default(const std::string& dir, const std::string file, 
        std::uint32_t size, std::uint32_t rotate_at, severity_level level) -> bool;
    

inline auto logger_handle = [] () mutable -> logger_type_t& {
    return global_logger::get();
};

// Allow for formatting a number with comma
template<typename T>
struct number_printer
{
    static_assert(std::is_arithmetic_v<T> == true);
    explicit number_printer(const T& v) : value{v} {

    }

    auto format () const -> std::string {
        struct internal: public std::numpunct<char>{
        protected:
            virtual char do_thousands_sep() const{return ',';}
            virtual std::string do_grouping() const{return "\03";}
        };
        std::stringstream ss;
        ss.imbue({std::locale(), new internal});
        ss << std::setprecision(2) << std::fixed << value;
        return ss.str();
    }

    const T& value;
};
template<typename T> inline 
auto operator << (std::ostream& os, number_printer<T> p) -> std::ostream& {
    return os << p.format();
}

template<typename T> inline 
auto to_string(number_printer<T> n) -> std::string {
    return n.format();
}

template<typename T> inline
auto number_formatter(T v) -> number_printer<T> {
    return number_printer<T>{v};
}

// Allow printing a number as bytes (1024 multiplications)
struct bytes_formatter
{
    explicit bytes_formatter(std::uint64_t v) : value{v} {
    }

    auto operator () () const -> std::string;

    std::uint64_t value;
};

inline auto operator << (std::ostream& os, bytes_formatter b) -> std::ostream& {
    return os << b();
}
