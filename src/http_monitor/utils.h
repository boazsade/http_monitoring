#pragma once

namespace std 
{
class thread;
}	// end of std namespace

namespace utils
{
auto rename_thread(std::thread& thread, const char* name) -> void;
}	// end of local namespace

