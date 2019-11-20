cmake_minimum_required(VERSION 2.8)

project(pack_stat)
include_directories(${CMAKE_SOURCE_DIR}/ssn_track)
link_directories(${CMAKE_SOURCE_DIR}/ssn_track)
add_subdirectory(ssn_track) 
add_executable(pack_stat pack_stat.cc pcap_stat_decode.cc)
target_link_libraries(pack_stat pcap ssn_track)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g")

