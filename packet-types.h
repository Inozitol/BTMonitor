#pragma once

#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string>
#include <chrono>
#include "bt-types.h"

using micro_timepoint = std::chrono::time_point<std::chrono::system_clock, std::chrono::microseconds>;

struct packet_data_t {
    micro_timepoint ts{};
    in_addr ip_src{};
    in_addr ip_dst{};
    u_char l4_p{};
    u_short l4_src{};
    u_short l4_dst{};
    bt_type_t bt_t = bt_type_t::UNKNOWN;
    std::string payload;

    packet_data_t() = default;
};
