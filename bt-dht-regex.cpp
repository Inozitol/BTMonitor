#include <iostream>
#include "bt-dht-regex.h"


bt_type_t dht_regex::query_match(const std::string &payload) {

    bt_type_t type = bt_type_t::UNKNOWN;

    for(auto& pair : DHT_QUERY_VEC){
        if(std::regex_search(payload,pair.first)){
            type = pair.second;
            break;
        }
    }

    uint8_t id_len;
    std::smatch match;

    if(!std::regex_search(payload,match, TRANSACTION_CODE))
        return bt_type_t::UNKNOWN;

    std::size_t transaction_pos = match.position(0);
    transaction_pos += 5;
    id_len = std::stoi(match[1]);

    std::string transaction_id(payload,transaction_pos, id_len);
    query_history.insert({transaction_id, {type,std::chrono::steady_clock::now()}});

    return type;
}

bt_type_t dht_regex::response_match(const std::string &payload) {

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
        type = query_history.at(transaction_id).first;
        query_history.erase(transaction_id);
        switch(type){
            case bt_type_t::QUERY_PING:
                return bt_type_t::RESPONSE_PING;
            case bt_type_t::QUERY_FIND_NODE:
                return bt_type_t::RESPONSE_FIND_NODE;

            case bt_type_t::QUERY_GET_PEERS:
                return bt_type_t::RESPONSE_GET_PEERS;

            case bt_type_t::QUERY_ANNOUNCE_PEER:
                return bt_type_t::RESPONSE_ANNOUNCE_PEER;

            case bt_type_t::UNKNOWN:
            default:
                return bt_type_t::UNKNOWN;
        }
    }
    return bt_type_t::UNKNOWN;
}

bt_type_t dht_regex::match(const std::string& payload) {
    if(std::regex_search(payload, DHT_QUERY_HEAD))
        return query_match(payload);

    if(std::regex_search(payload, DHT_RESPONSE_HEAD))
        return response_match(payload);

    return bt_type_t::UNKNOWN;
}

void clean_history(){
    dht_regex::history_mutex.lock();
    auto now = std::chrono::steady_clock::now();
    for(auto entry = dht_regex::query_history.cbegin(); entry != dht_regex::query_history.cend();){
        if(std::chrono::duration(now - entry->second.second).count() > 60) {
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
            auto interval = std::chrono::steady_clock::now() + std::chrono::seconds(period);
            clean_history();
            std::this_thread::sleep_until(interval);
        }
    }).detach();
}
