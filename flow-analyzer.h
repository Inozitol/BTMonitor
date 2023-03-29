#pragma once

#include <unordered_map>
#include <vector>
#include <functional>
#include <mutex>
#include "flow-keys-types.h"
#include "flow-types.h"
#include "thread-killer.h"

namespace flow_analyzer{

    /** Mutex to lock flow_map in multi-threading situations */
    extern std::mutex flows_mutex;

    /** Unordered hashmap holding all flows */
    extern std::unordered_map<bidirectional_flow_key_t, bidirectional_flow, defined_hash> flow_map;

    /**
     * @brief Inserts the packet into appropriate flow_analyzer::flow_map field
     *
     * This function will generate a bidirectional_flow_key_t from a given packet and
     * uses that key to either create a new flow with that packet, or insert the packet
     * into existing flow.
     *
     * @param pkt Packet to insert into flow_analyzer::flow_map
     */
    void process_pkt(const packet_data_t& pkt);

    /**
     * @brief Starts a thread checking for timed out flows on a given period in seconds.
     * @param period Running period of a thread checking timed out flows
     */
    void timeout_clear_start(uint32_t period);

    /**
     * @brief Function that checks all the flows inside flow_analyzer::flow_map for timed out flows. Invoked by flow_analyzer::timeout_clear_start.
     */
    void clean_timeouts();

};