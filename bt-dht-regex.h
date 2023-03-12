#pragma once

#include <vector>
#include <string>
#include <regex>
#include <mutex>
#include <thread>
#include <chrono>
#include "bt-types.h"

namespace dht_regex{

    /// A regular expression that should be followed by a transaction id of a DHT packet
    /// (see https://www.bittorrent.org/beps/bep_0005.html #KRPC Protocol)
    const std::regex TRANSACTION_CODE(R"(1:t(\d):)");

    /// Hash map of already captured DHT queries
    /// This is used to associate replies with queries so that we know to what type of query it is replying
    static std::unordered_map<std::string, std::pair<bt_type_t,std::chrono::steady_clock::time_point>> query_history;

    /// query_history is a shared resource so we need to lock it between threads
    static std::mutex history_mutex;

    /// A regular expression used to discover whether a UDP packet is used as a DHT Query
    const std::regex DHT_QUERY_HEAD(R"(1:ad2:id20)");
    /// Vector of regular expressions used to differentiate different DHT queries
    const std::vector<std::pair<std::regex,bt_type_t>> DHT_QUERY_VEC {
        {std::regex(R"(1:q4:ping)",std::regex::extended),           bt_type_t::QUERY_PING},
        {std::regex(R"(1:q9:find_node)",std::regex::extended),      bt_type_t::QUERY_FIND_NODE},
        {std::regex(R"(1:q9:get_peers)",std::regex::extended),      bt_type_t::QUERY_GET_PEERS},
        {std::regex(R"(1:q13:announce_peer)",std::regex::extended), bt_type_t::QUERY_ANNOUNCE_PEER}
    };

    /// A regular expression used to discover whether a UDP packet is used as a DHT Reply
    const std::regex DHT_RESPONSE_HEAD(R"(1:rd2:id20)");

    /// Try and match against DHT Query regex
    bt_type_t query_match(const std::string& payload);

    /// Try and match against DHT Reply regex
    bt_type_t response_match(const std::string& payload);

    /// Try and match against any UDP regex
    bt_type_t match(const std::string& payload);

    /// Function to start periodic cleanup of query_history
    void history_clear_start(uint32_t period);
}