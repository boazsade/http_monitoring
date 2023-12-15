#include "output_data.h"
#include <iostream>

namespace monitor
{

auto operator << (std::ostream& os, const output_data& od) -> std::ostream& {
    //constexpr std::size_t MAX_SIZE = 128;

    auto max_size = od.payload.size();//std::min(od.payload.size(), MAX_SIZE);
    return os<<"id: "<<std::hex<<od.id<<", UUID: "<<od.uuid<<", host: "<<od.host
            <<", payload size: "<<std::dec<<od.payload.size()<<"\npayload:\n"
            <<std::string_view(od.payload.data(), max_size);
}

}       // end of monitor namespace
