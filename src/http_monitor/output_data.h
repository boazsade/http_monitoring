#pragma once

#include <string>
#include <iosfwd>

namespace monitor
{
// This data type is the information that we are transmitting
// from this module to the "consumer"
// it contain the json message as well as other parameters that
// required to send to the remote receiver
struct output_data
{
    uint64_t        id = 0;
    std::string     uuid;
    std::string     host;
    std::string     payload;

    output_data() = default;
    output_data(uint64_t i, std::string_view uid, std::string_view h, std::string&& pl) :
        id{i}, uuid{uid}, host{h}, payload{std::move(pl)} {
    }

}; 

auto operator << (std::ostream& os, const output_data& od) -> std::ostream&;

}       // end of monitor namespace
