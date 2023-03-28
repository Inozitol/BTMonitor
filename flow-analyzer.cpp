
#include "flow-analyzer.h"

#include "utils.h"

std::mutex flow_analyzer::flows_mutex;
std::unordered_map<bidirectional_flow_key_t, bidirectional_flow, defined_hash> flow_analyzer::flow_map;

void flow_analyzer::process_pkt(const packet_data_t& pkt){
    const auto key = bidirectional_flow_key_t(pkt);
    flows_mutex.lock();
    flow_map[key].add_packet(pkt);
    flows_mutex.unlock();
}

void flow_analyzer::timeout_clear_start(uint32_t period) {
    tasks.push_back( std::async(std::launch::async,[period](){
        while(true){
            if(!thread_killer.wait_for(std::chrono::seconds(period))){
                clean_timeouts();
                break;
            }
            clean_timeouts();
        }
    }));
}

void flow_analyzer::clean_timeouts(){
    flows_mutex.lock();
    for(auto it = flow_map.cbegin(); it != flow_map.cend();){
        auto now = std::chrono::system_clock::now();
        auto now_micro = std::chrono::time_point_cast<std::chrono::microseconds>(now);

        if(timeout_check(it->second._packets.back().ts, now_micro)){
            it->second.output_flow();
            flow_map.erase(it++);
        }else{
            ++it;
        }
    }
    flows_mutex.unlock();
}
