cmake_minimum_required(VERSION 3.0)

add_executable(test_pack_stats test.cc ../tcp.cc ../pcap_stat_decode.cc)

include_directories(test_pack_stats ${PROJECT_SOURCE_DIR} ${PROJECT_BINARY_DIR})
link_directories(test_pack_stats ${PROJECT_SOURCE_DIR})
target_link_libraries(test_pack_stats ssn_track)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -std=c++11")
