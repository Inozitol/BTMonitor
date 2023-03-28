#include "flow-types.h"
#include "flow-analyzer.h"
#include "utils.h"

void bidirectional_flow::add_packet(const packet_data_t& pkt) {
    if(_packets.size() > 1){
        if(pkt_pair_timeout_check(_packets.back(), pkt)){
            this->output_flow();
            _packets.clear();
        }
    }
    _packets.push_back(pkt);
}

void bidirectional_flow::output_flow() const{
    flow_data_t data{};
    data.header_info = direct_flow_t(*_packets.begin());
    data.pkt_count = _packets.size();
    for(auto& pkt : _packets){
        data.total_payload += pkt.payload.length();
    }
    data.flow_type = bt_type_t::UNKNOWN;
    data.from = std::chrono::system_clock::to_time_t(_packets.front().ts);
    data.to = std::chrono::system_clock::to_time_t(_packets.back().ts);

    ::output_flow(data);
}