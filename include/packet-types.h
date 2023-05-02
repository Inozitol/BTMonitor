#pragma once

#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string>
#include <chrono>
#include "bt-types.h"

using micro_timepoint = std::chrono::time_point<std::chrono::system_clock, std::chrono::microseconds>;

/**
 * @struct packet_data_t
 * @brief Data defining a packet
 */
struct packet_data_t {
    micro_timepoint timestamp{};    ///< Timestamp of packet
    in_addr ip_src{};               ///< Source IP
    in_addr ip_dst{};               ///< Destination IP
    u_char l4_p{};                  ///< Layer 4 Protocol
    u_short l4_src{};               ///< Layer 4 Source Port
    u_short l4_dst{};               ///< Layer 4 Destination Port
    std::string payload;            ///< Payload of packet

    packet_data_t() = default;
};
