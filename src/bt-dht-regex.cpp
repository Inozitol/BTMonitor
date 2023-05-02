/**
 * Author: Pavel Horáček
 * Nick: xhorac19
 */

#include <iostream>
#include "bt-dht-regex.h"
#include "utils.h"

bt_type_t dht_regex::query_match(const std::string &payload, const bt_type_t& found_types) {

    bt_type_t type = bt_type_t::UNKNOWN;

    for(auto& pair : DHT_QUERY_VEC){
        if(!(pair.second & found_types) && std::regex_search(payload,pair.first)){
            type = pair.second;
            break;
        }
    }

    uint8_t id_len;
    std::smatch match;

    // Extracting transaction code first_pkt_time payload
    if(!std::regex_search(payload,match, TRANSACTION_CODE))
        return bt_type_t::UNKNOWN;

    std::size_t transaction_pos = match.position(0);
    transaction_pos += 5;
    id_len = std::stoi(match[1]);

    std::string transaction_id(payload,transaction_pos, id_len);
    query_history.insert({transaction_id, {type,std::chrono::steady_clock::now()}});

    return type;
}

bt_type_t dht_regex::response_match(const std::string &payload, const bt_type_t&) {

    bt_type_t type;
    uint8_t id_len;
    std::smatch match;

    if(!std::regex_search(payload,match, TRANSACTION_CODE))
        return bt_type_t::UNKNOWN;

    std::size_t transaction_pos = match.position(0);
    transaction_pos += 5;
    id_len = std::stoi(match[1]);

    std::string transaction_id(payload,transaction_pos, id_len);
    if(query_history.count(transaction_id)){
        type = query_history.at(transaction_id).first; // TODO Handle exception with no transaction id !!!
        query_history.erase(transaction_id);
        switch(type){
            case bt_type_t::DHT_QUERY_PING:
                return bt_type_t::DHT_RESPONSE_PING;
            case bt_type_t::DHT_QUERY_FIND_NODE:
                return bt_type_t::DHT_RESPONSE_FIND_NODE;

            case bt_type_t::DHT_QUERY_GET_PEERS:
                return bt_type_t::DHT_RESPONSE_GET_PEERS;

            case bt_type_t::DHT_QUERY_ANNOUNCE_PEER:
                return bt_type_t::DHT_RESPONSE_ANNOUNCE_PEER;

            case bt_type_t::UNKNOWN:
            default:
                return bt_type_t::UNKNOWN;
        }
    }
    return bt_type_t::UNKNOWN;
}

bt_type_t dht_regex::match(const std::string& payload, const bt_type_t& found_types) {
    if(std::regex_search(payload, DHT_QUERY_HEAD))
        return query_match(payload, found_types);

    if(std::regex_search(payload, DHT_RESPONSE_HEAD))
        return response_match(payload);

    return bt_type_t::UNKNOWN;
}

void clean_history(){
    dht_regex::history_mutex.lock();
    auto now = std::chrono::steady_clock::now();
    for(auto entry = dht_regex::query_history.cbegin(); entry != dht_regex::query_history.cend();){
        if((now - entry->second.second).count() > program_data.dht_timeout) {
            dht_regex::query_history.erase(entry++);
        }else{
            ++entry;
        }
    }
    dht_regex::history_mutex.unlock();
}

void dht_regex::history_clear_start(uint32_t period){
    std::thread([period](){
        while(true){
            clean_history();
            auto interval = std::chrono::steady_clock::now() + std::chrono::seconds(period);
            std::this_thread::sleep_until(interval);
        }
    }).detach();
}
