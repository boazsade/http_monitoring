# boost support
option(USE_STATIC_BOOST "Build with static BOOST libraries instead of dynamic" ON)
set(Boost_USE_STATIC_LIBS ${USE_STATIC_BOOST})
set(Boost_USE_MULTITHREADED ON)
unset(Boost_INCLUDE_DIR CACHE)
unset(Boost_LIBRARY_DIRS CACHE)
find_package(Boost REQUIRED COMPONENTS thread context system coroutine log regex program_options)
if(USE_STATIC_BOOST)
   message(STATUS "Linking against boost static libraries")
else()
   message(STATUS "Linking against boost dynamic libraries")
endif()

