#pragma once

#include <vector>
#include <chrono>
#include <thread>
#include <future>
#include "packet-types.h"
#include "flow-types.h"
#include "bt-types.h"
#include "flow-keys-types.h"
#include "thread-killer.h"

struct directional_flow_key_t;

extern std::future<void> timeout_task;

/** @struct flow_data_t
 * @brief Data holding information extracted from one bidirectional flow.
 * @var src_info Information about a one way flow (which direction doesn't matter)
 * @var pkt_count Number of packets in a flow
 * @var total_payload Total amount of data in bytes
 * @var flow_type Type of BitTorrent traffic inside the flow
 * @var from Timestamp of first packet
 * @var to Timestamp of last packet
 */
struct flow_data_t{
    directional_flow_key_t src_info;
    std::size_t pkt_count;
    uint32_t total_payload;
    bt_type_t flow_type;
    std::time_t from;
    std::time_t to;
};

/** @struct bidirectional_flow_data
 * @brief Struct defining data and methods for one bidirectional flow.
 * @var packets Vector with ordered packets inside the flow
 * @var src Direct flow defined from first captured packet to remember source direction
 */
struct bidirectional_flow_data{
    std::vector<packet_data_t> packets;

    bidirectional_flow_data() = default;
    void add_packet(const packet_data_t&);
    void output_flow() const;
    [[nodiscard]] bt_type_t analyze_flow() const;
};
