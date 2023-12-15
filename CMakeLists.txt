cmake_minimum_required(VERSION 3.0.0)
project(http_monitoring)
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_LIST_DIR}/cmake)


include_directories("${PROJECT_BINARY_DIR}")

set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 17)

add_subdirectory(example)
add_subdirectory(src)


set(CPACK_PROJECT_NAME ${PROJECT_NAME})
include(CPack) 


# test support
enable_testing()
