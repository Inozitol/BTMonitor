#include "flow-types.h"
#include "utils.h"
#include "pkt-analyzer.h"

void flow_info_t::update_flow_info(const packet_data_t& pkt){
    if(pkt_count == 0){
        first_pkt_time = pkt.timestamp;
        src_info = directional_flow_key_t(pkt);
    }else if(timeout_check(last_pkt_time, pkt.timestamp)){
        output_flow(*this);
        clear_info();
        first_pkt_time = pkt.timestamp;
        src_info = directional_flow_key_t(pkt);
    }
    last_pkt_time = pkt.timestamp;
    total_payload += pkt.payload.length();
    pkt_count+=1;
    if(pkt_count < program_data.max_packets){
        flow_type |= analyze_packet(pkt);
    }
}

void flow_info_t::clear_info() {
    total_payload = 0;
    pkt_count = 0;
}
