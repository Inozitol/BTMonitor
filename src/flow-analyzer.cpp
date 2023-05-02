/**
 * Author: Pavel Horáček
 * Nick: xhorac19
 */

#include "flow-analyzer.h"
#include "utils.h"

std::mutex flow_analyzer::flows_mutex;
flow_analyzer::flow_map_t flow_analyzer::flow_table;

void flow_analyzer::process_pkt(packet_data_t& pkt){
    const auto key = flow_key_t(pkt);
    std::unique_lock<std::mutex> lck(flows_mutex);
    flow_table[key].update_flow_info(pkt);
}

void flow_analyzer::timeout_clear_start(uint32_t period) {
    std::thread([period](){
        while(true){
            clean_timeouts();
            auto interval = std::chrono::steady_clock::now() + std::chrono::seconds(period);
            std::this_thread::sleep_until(interval);
        }
    }).detach();
}

void flow_analyzer::clean_timeouts(){
    std::unique_lock<std::mutex> lck(flows_mutex);
    for(auto it = flow_table.begin(); it != flow_table.end();){
        auto now = std::chrono::system_clock::now();
        auto now_micro = std::chrono::time_point_cast<std::chrono::microseconds>(now);

        if(timeout_check(it->second.last_pkt_time, now_micro)){
            output_flow(it->second);
            flow_table.erase(it++);
        }else{
            ++it;
        }
    }
}

void flow_analyzer::output_flows(){
    for(auto it = flow_table.begin(); it != flow_table.end();){
        output_flow(it->second);
        flow_table.erase(it++);
    }
}