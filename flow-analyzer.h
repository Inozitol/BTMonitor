#pragma once

#include <unordered_map>
#include <vector>
#include <functional>
#include <mutex>
#include "flow-keys-types.h"
#include "flow-types.h"
#include "thread-killer.h"

namespace flow_analyzer{

    extern std::mutex flows_mutex;
    extern std::unordered_map<bidirectional_flow_key_t, bidirectional_flow, defined_hash> flow_map;

    void process_pkt(const packet_data_t& pkt);
    void timeout_clear_start(uint32_t period);
    void clean_timeouts();

};