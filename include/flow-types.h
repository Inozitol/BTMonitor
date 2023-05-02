/**
 * Author: Pavel Horáček
 * Nick: xhorac19
 */

#pragma once

#include <vector>
#include <chrono>
#include <thread>
#include <future>

#include "packet-types.h"
#include "flow-types.h"
#include "bt-types.h"
#include "flow-keys-types.h"

struct directional_flow_key_t;

using micro_timepoint = std::chrono::time_point<std::chrono::system_clock, std::chrono::microseconds>;

/**
 * @struct flow_info_t
 * @brief Struct defining data and methods for flow info.
 */
struct flow_info_t{
    directional_flow_key_t src_info{};          ///< Network information about the flow in form of directional_flow_key_t
    std::size_t pkt_count = 0;                  ///< Number of packets
    uint32_t total_payload = 0;                 ///< Number of bytes transmitted through
    bt_type_t flow_type = bt_type_t::UNKNOWN;   ///< Bitmap of BitTorrent types gathered
    micro_timepoint first_pkt_time;             ///< Timestamp of the first packet
    micro_timepoint last_pkt_time;              ///< Timestamp of the last packet

    flow_info_t() = default;

    /**
     * @brief Updates the flow with information from a new packet
     * @param pkt New packet of the flow
     */
    void update_flow_info(const packet_data_t &pkt);

    /**
     * @brief Clears this structure into a fresh state
     */
    void clear_info();
};
