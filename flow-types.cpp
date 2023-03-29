#include "flow-types.h"
#include "flow-analyzer.h"
#include "utils.h"

void bidirectional_flow::add_packet(const packet_data_t& pkt) {
    if(packets.size() > 1){
        if(pkt_pair_timeout_check(packets.back(), pkt)){
            this->output_flow();
            packets.clear();
        }
    }
    packets.push_back(pkt);
}

void bidirectional_flow::output_flow() const{
    flow_data_t data{};
    data.header_info = direct_flow_t(*packets.begin());
    data.pkt_count = packets.size();
    for(auto& pkt : packets){
        data.total_payload += pkt.payload.length();
    }
    data.flow_type = bt_type_t::UNKNOWN;
    data.from = std::chrono::system_clock::to_time_t(packets.front().ts);
    data.to = std::chrono::system_clock::to_time_t(packets.back().ts);

    ::output_flow(data);
}