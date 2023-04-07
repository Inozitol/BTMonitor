cmake_minimum_required(VERSION 3.18)
project(BTMonitor)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")

include(FindPCAP.cmake)

set(SOURCE_FILES main.cpp bt-dht-regex.cpp bt-dns-regex.cpp flow-keys-types.cpp utils.cpp flow-analyzer.cpp flow-types.cpp thread-killer.cpp bt-pp-regex.cpp)
add_executable(BTMonitor ${SOURCE_FILES})
target_link_libraries(BTMonitor ${PCAP_LIBRARY})
