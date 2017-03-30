cmake_minimum_required(VERSION 3.2)

set( PROJECT udp_packet_filter_tests )
project( ${PROJECT} )

SET( CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS} "-std=c++11" )
SET( CMAKE_BUILD_TYPE Debug )

file( GLOB_RECURSE SOURCES "*.hpp" "*.cpp" )

add_executable (${PROJECT} ${SOURCES} )
target_link_libraries( ${PROJECT} pcap )
