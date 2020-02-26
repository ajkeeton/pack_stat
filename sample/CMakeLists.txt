cmake_minimum_required(VERSION 3.0)

add_executable(pstats pstats.cc)

include_directories(pstats ${PROJECT_SOURCE_DIR} ${PROJECT_BINARY_DIR})
link_directories(pstats ${PROJECT_SOURCE_DIR})
target_link_libraries(pstats pack_stat pcap)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -std=c++11")
