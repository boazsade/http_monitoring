#pragma once
#include <string>

enum class ChannelIndices : std::uint16_t {
    PACKET_MONITOR = 0,
    LAST_ENTRY  // make sure to add new ones before this one
};

constexpr std::string_view ALL_CHANNEL_NAMES[] = {
        "http_packets_monitor",
};

auto operator << (std::ostream& os, ChannelIndices ci) -> std::ostream&;

inline constexpr auto _channel_name(ChannelIndices index) -> std::string_view {
    return ALL_CHANNEL_NAMES[static_cast<std::uint16_t>(index)];
}

const std::string DEFAULT_HTTP_CHANNEL = std::string(_channel_name(ChannelIndices::PACKET_MONITOR));
