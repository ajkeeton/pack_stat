cmake_minimum_required(VERSION 2.8)

add_executable(pack_stat pack_stat.cc ssn_track.cc pcap_stat_decode.cc)
target_link_libraries(pack_stat pcap)

include_directories(${CMAKE_SOURCE_DIR})

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g")
