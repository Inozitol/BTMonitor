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
extern std::vector <std::future<void>> tasks;

struct flow_data_t{
    direct_flow_t header_info;
    std::size_t pkt_count;
    uint32_t total_payload;
    bt_type_t flow_type;
    std::time_t from;
    std::time_t to;
};

struct bidirectional_flow{
    std::vector<packet_data_t> _packets;

    bidirectional_flow() = default;
    void add_packet(const packet_data_t&);
    void output_flow() const;
};
