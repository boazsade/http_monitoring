#include "channel.h"

namespace monitor
{

channel::channel() : com{std::make_shared<com_type>()} {
}

auto channel::send(element_type new_session) -> bool {
    return com->push(std::move(new_session));
}

auto channel::empty() const -> bool {
    return no_input() && no_output();
}

auto channel::no_input() const -> bool {
    return com->write_available() == 0;
}

auto channel::no_output() const -> bool {
    return com->read_available() == 0;
}

}   // end of namespace monitor
