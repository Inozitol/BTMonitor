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

struct direct_flow_t;

extern std::future<void> timeout_task;

/** @struct flow_data_t
 * @brief Data holding information extracted from one bidirectional flow.
 * @var direct_flow_t Information about a one way flow (which direction doesn't matter)
 * @var pkt_count Number of packets in a flow
 * @var total_payload Total amount of data in bytes
 * @var flow_type Type of BitTorrent traffic inside the flow
 * @var from Timestamp of first packet
 * @var to Timestamp of last packet
 */
struct flow_data_t{
    direct_flow_t header_info;
    std::size_t pkt_count;
    uint32_t total_payload;
    bt_type_t flow_type;
    std::time_t from;
    std::time_t to;
};

/** @struct bidirectional_flow
 * @brief Struct defining data and methods for one bidirectional flow.
 * @var packets Vector with ordered packets inside the flow
 */
struct bidirectional_flow{
    std::vector<packet_data_t> packets;

    bidirectional_flow() = default;
    void add_packet(const packet_data_t&);
    void output_flow() const;
};
