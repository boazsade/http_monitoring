# This would set the warning and other common flags
if(MSVC)
  # Force to always compile with W4
  if(CMAKE_CXX_FLAGS MATCHES "/W[0-4]")
    string(REGEX REPLACE "/W[0-4]" "/W4" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
  else()
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W4")
  endif()
elseif(CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_GNUCXX)
  # Update if necessary
  # https://gcc.gnu.org/onlinedocs/gcc/Warning-Options.html
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wno-long-long -pedantic -Wextra -Wformat -Wformat-security") 
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wformat-overflow -Wnull-dereference -Wnonnull") 
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Woverlength-strings")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-builtin-declaration-mismatch") 
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wlogical-op -Wfloat-conversion -Wdangling-else -Wconversion -Wcast-align -Wcast-qual -Wshadow")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wfloat-equal -Wstringop-overflow")
  # we would like to keep 0 warning, so if we are not running with the 
  # static analyzer, we would like to turn warning to errors. Because we
  # are not yet ready with static analyzer, this is disabled for now, but it
  # should be changes later
  if (ENABLE_CLANG_TIDY)
    message(STATUS "disabling warning as error, as we are running with clang-tidy")
  else(ENABLE_CLANG_TIDY)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Werror")
  endif()
  if (ENABLE_MEMORY_PROFILER)
    message(STATUS "🟢 enabling memory profiler")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address")
  endif(ENABLE_MEMORY_PROFILER)
endif()
set(CMAKE_EXPORT_COMPILE_COMMANDS ON) 


