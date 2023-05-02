/**
 * Author: Pavel Horáček
 * Nick: xhorac19
 */

#pragma once

#include <vector>
#include <string>
#include <regex>
#include <mutex>
#include <thread>
#include <chrono>
#include <unordered_map>
#include "bt-types.h"

namespace dht_regex{

    /**
     * A regular expression that extracts the length and position of a transaction id in KRPC packet
     * (see https://www.bittorrent.org/beps/bep_0005.html #KRPC Protocol)
     */
    const std::regex TRANSACTION_CODE(R"(1:t(\d):)");

    /**
     * Hash map of already captured KRPC queries
     * This is used to associate replies with queries so that we know to what type of query it is replying
     */
    static std::unordered_map<std::string, std::pair<bt_type_t,std::chrono::steady_clock::time_point>> query_history;

    /** query_history is a shared resource so we need to lock it between threads by a mutex **/
    static std::mutex history_mutex;

    /** A regular expression used to discover whether a UDP packet is used as a KRPC Query */
    const std::regex DHT_QUERY_HEAD(R"(1:ad2:id20)");

    /** Vector of regular expressions used to differentiate different KRPC queries */
    const std::vector<std::pair<std::regex,bt_type_t>> DHT_QUERY_VEC {
        {std::regex(R"(1:q4:ping)",std::regex::extended),           bt_type_t::DHT_QUERY_PING},
        {std::regex(R"(1:q9:find_node)",std::regex::extended),      bt_type_t::DHT_QUERY_FIND_NODE},
        {std::regex(R"(1:q9:get_peers)",std::regex::extended),      bt_type_t::DHT_QUERY_GET_PEERS},
        {std::regex(R"(1:q13:announce_peer)",std::regex::extended), bt_type_t::DHT_QUERY_ANNOUNCE_PEER}
    };

    /** A regular expression used to discover whether a UDP packet is used as a KRPC Reply */
    const std::regex DHT_RESPONSE_HEAD(R"(1:rd2:id20)");

    /**
     * @brief Function tries to match KRPC query regexes against the packet payload. This function should be called by bt_dht::match.
     * @param payload Packet payload
     * @param found_types Types that have been already found inside the flow. These will not be checked.
     * @return Type of BitTorrent communication inside the packet
     */
    bt_type_t query_match(const std::string& payload, const bt_type_t& found_types = bt_type_t::UNKNOWN);

    /**
     * @brief Function tries to match KRPC reply regexes against the packet payload. This function should be called by bt_dht::match.
     * @param payload Packet payload
     * @param found_types Types that have been already found inside the flow. These will not be checked.
     * @return Type of BitTorrent communication inside the packet
     */
    bt_type_t response_match(const std::string& payload, const bt_type_t& found_types = bt_type_t::UNKNOWN);

    /**
     * @brief Function tries to match KRPC regexes against the packet payload
     * @param payload Packet payload
     * @param found_types Types that have been already found inside the flow. These will not be checked.
     * @return Type of BitTorrent communication inside the packet
     */
     bt_type_t match(const std::string& payload, const bt_type_t& found_types = bt_type_t::UNKNOWN);

    /**
     * @brief Function starts periodic cleanup of query_history table
     * @param period Period of cleanup in seconds
     */
    void history_clear_start(uint32_t period);
}
