#pragma once

#include <fstream>
#include <istream>
#include <iomanip>
#include <iostream>
#include <sys/time.h>
#include "packet-types.h"
#include "flow-types.h"
#include "bt-types.h"

enum program_flags_t : u_int8_t {
    manual_interface = 1 << 0,
    offline_mode     = 1 << 1,
    to_file          = 1 << 2,
    to_stdout        = 1 << 3,
    only_bt          = 1 << 4,
    flow_mode        = 1 << 5,
    flow_timeout     = 1 << 6
};

inline program_flags_t operator|(program_flags_t ls, program_flags_t rs){
    return static_cast<program_flags_t>(static_cast<u_int8_t>(ls) | static_cast<u_int8_t>(rs));
}

inline bool operator&(program_flags_t ls, program_flags_t rs){
    return (static_cast<program_flags_t>(static_cast<u_int8_t>(ls) & static_cast<u_int8_t>(rs)) == rs);
}

inline program_flags_t& operator|=(program_flags_t &ls, program_flags_t rs){
    return ls = static_cast<program_flags_t>(ls | rs);
}

struct program_data_t{
    std::string interface;
    std::ofstream out_file;
    std::string pcap_file;
    uint16_t flow_wait = 1;
    uint64_t flow_timeout = 1000000;    // Microseconds
    program_flags_t program_flags{};
};

extern program_data_t program_data;

void init_csv();

void output_pkt(const packet_data_t& pkt);

struct flow_data_t;
void output_flow(const flow_data_t& flow);

inline void hash_combine(std::size_t& seed, const std::size_t& hash){
    seed ^= hash + 0x9e3779b9 + (seed << 6) + (seed >> 2);
}

using micro_timepoint = std::chrono::time_point<std::chrono::system_clock, std::chrono::microseconds>;

constexpr std::chrono::microseconds timeval2duration(timeval ts){
    using namespace std::chrono;

    auto duration = seconds{ts.tv_sec} + microseconds {ts.tv_usec};
    return duration_cast<microseconds>(duration);
}

constexpr micro_timepoint timeval2timepoint(timeval ts){
    using namespace std::chrono;

    return time_point<system_clock, microseconds>{timeval2duration(ts)};
}

bool pkt_pair_timeout_check(const packet_data_t& early_pkt, const packet_data_t& late_pkt);

bool timeout_check(const micro_timepoint& early_ts, const micro_timepoint& late_ts);