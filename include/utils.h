#pragma once

#include <fstream>
#include <istream>
#include <iomanip>
#include <iostream>
#include <sys/time.h>

#include "packet-types.h"
#include "flow-types.h"
#include "bt-types.h"

/**
 * Enumeration of program input options
 */
enum program_flags_t : u_int8_t {
    manual_interface = 1 << 0,
    offline_mode     = 1 << 1,
    to_file          = 1 << 2,
    to_stdout        = 1 << 3,
    only_bt          = 1 << 4,
    well_defined     = 1 << 5,
    promisc          = 1 << 6
};

/// Various operators for enumeration program_flags_t to make usage as bitmap easier

inline program_flags_t operator|(program_flags_t ls, program_flags_t rs){
    return static_cast<program_flags_t>(static_cast<u_int8_t>(ls) | static_cast<u_int8_t>(rs));
}

inline bool operator&(program_flags_t ls, program_flags_t rs){
    return (static_cast<program_flags_t>(static_cast<u_int8_t>(ls) & static_cast<u_int8_t>(rs)) == rs);
}

inline program_flags_t& operator|=(program_flags_t &ls, program_flags_t rs){
    return ls = static_cast<program_flags_t>(ls | rs);
}

/**
 * @struct program_data_t
 * @brief Structure that holds user configurable parameters
 */
struct program_data_t{
    std::string interface;                  ///< String with the name of the interface.
    std::ofstream out_file;                 ///< Opened output file.
    std::string pcap_file;                  ///< Name of the pcap file being analyzed.
    uint16_t dht_wait = 30;                 ///< Period in seconds on which a secondary thread checks for expired DHT query records
    uint64_t dht_timeout = 60000000;        ///< Timeout period of DHT query records in microseconds
    uint16_t flow_wait = 30;                ///< Period in seconds on which a secondary thread checks for expired flow records
    uint64_t flow_timeout = 60000000;       ///< Timeout period of flow records in microseconds
    program_flags_t program_flags{};        ///< Bitmap of various program options
    uint32_t max_packets = 10;              ///< Maximum number of packets per flow to be inspected for BitTorrent signatures
};

extern program_data_t program_data;

/**
 * @brief Initializes CSV file with a header
 */
void init_csv();

/**
 * @brief Outputs flow into stdout, CSV file, or both
 * @param info Flow into to be outputted
 */
void output_flow(const flow_info_t& info);

/**
 * @brief Algorithm for combining hashes
 * Inspired by: https://stackoverflow.com/a/2595226
 * @param seed Seed of the hash that's changing
 * @param hash New hash to be applied on seed
 */
inline void hash_combine(std::size_t& seed, const std::size_t& hash){
    seed ^= hash + 0x9e3779b9 + (seed << 6) + (seed >> 2);
}

using micro_timepoint = std::chrono::time_point<std::chrono::system_clock, std::chrono::microseconds>;

/**
 * @brief Converts type of timeval to chrono::microseconds
 * @param ts Timeval value
 * @return ts in chrono::microseconds
 */
constexpr std::chrono::microseconds timeval2duration(timeval ts){
    using namespace std::chrono;

    auto duration = seconds{ts.tv_sec} + microseconds {ts.tv_usec};
    return duration_cast<microseconds>(duration);
}

/**
 * @brief Converts type of timeval to chrono::time_point<chrono::system_clock, chrono::microseconds>
 * @param ts Timeval value
 * @return ts in chrono::microseconds
 */
constexpr micro_timepoint timeval2timepoint(timeval ts){
    using namespace std::chrono;

    return time_point<system_clock, microseconds>{timeval2duration(ts)};
}

/**
 * @brief Checks if difference of two time points exceeds flow expiration duration
 * @param early_ts Time point that's earlier in time
 * @param late_ts  Time point that's later in time
 * @return True if it exceeds expiration duration, False if it doesn't.
 */
bool timeout_check(const micro_timepoint& early_ts, const micro_timepoint& late_ts);
