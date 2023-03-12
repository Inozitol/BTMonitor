cmake_minimum_required(VERSION 3.24)
project(BTMonitor)

set(CMAKE_CXX_STANDARD 17)

include(FindPCAP.cmake)

set(SOURCE_FILES main.cpp bt-dht-regex.cpp bt-dns-regex.cpp)
add_executable(BTMonitor ${SOURCE_FILES})
target_link_libraries(BTMonitor ${PCAP_LIBRARY})
