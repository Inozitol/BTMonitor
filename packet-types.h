#pragma once

#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string>
#include <chrono>
#include "bt-types.h"

using micro_timepoint = std::chrono::time_point<std::chrono::system_clock, std::chrono::microseconds>;

/** @struct packet_data_t
 * @brief Data defining a packet
 * @var timestamp Timestamp
 * @var ip_src Source IP
 * @var ip_dst Destination IP
 * @var l4_p Value found in field 'Protocol' of IP header
 * @var l4_src Source port of transport layer
 * @var l4_dst Destination port of transport layer
 * @var bt_t Type of BitTorrent traffic on this packet
 * @var payload Payload of the packet as seen by transport layer (only used in flow mode)
 */
struct packet_data_t {
    micro_timepoint timestamp{};
    in_addr ip_src{};
    in_addr ip_dst{};
    u_char l4_p{};
    u_short l4_src{};
    u_short l4_dst{};
    bt_type_t bt_t = bt_type_t::UNKNOWN;
    std::string payload;

    packet_data_t() = default;
};
