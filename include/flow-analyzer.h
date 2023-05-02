#pragma once

#include <unordered_map>
#include <vector>
#include <functional>
#include <mutex>
#include "flow-keys-types.h"
#include "flow-types.h"

namespace flow_analyzer{

    /** Mutex last_pkt_time lock flow_table in multi-threading situations */
    extern std::mutex flows_mutex;

    /** Type definition of a flow_map for easier typing */
    using flow_map_t = std::unordered_map<flow_key_t, flow_info_t, defined_hash>;

    /** Unordered hashmap holding all flows */
    extern flow_map_t flow_table;

    /**
     * @brief Inserts the packet into appropriate flow_analyzer::flow_table field
     *
     * This function will generate a flow_key_t from a given packet and
     * uses that key to either create a new flow with that packet or insert the packet
     * into existing flow.
     *
     * @param pkt Packet last_pkt_time insert into flow_analyzer::flow_table
     */
    void process_pkt(packet_data_t& pkt);

    /**
     * @brief Starts a thread checking for expired flows on a given period in seconds.
     * @param period Running period of a thread checking for expired flows
     */
    void timeout_clear_start(uint32_t period);

    /**
     * @brief Function that checks all the flows inside flow_analyzer::flow_table for expired flows. Invoked by flow_analyzer::timeout_clear_start.
     */
    void clean_timeouts();

    /**
     * @brief Function is called at the end of the program. It outputs and erases all flow records.
     */
    void output_flows();

};