cmake_minimum_required(VERSION 3.0)

project(pack_stat VERSION 0.1)

include_directories(${CMAKE_SOURCE_DIR}/ssn_track)
link_directories(${CMAKE_SOURCE_DIR}/ssn_track)
add_subdirectory(ssn_track) 
add_subdirectory(sample) 
add_subdirectory(tests) 
add_library(pack_stat pcap_stat_decode.cc tcp.cc)
target_link_libraries(pack_stat ssn_track ncurses)

