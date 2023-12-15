#include "utils.h"
#include <thread>
#include <pthread.h>

namespace utils
{

auto rename_thread(std::thread& thread, const char* name) -> void {
    pthread_setname_np(thread.native_handle(), name);
}

}	// end of namespace utils
