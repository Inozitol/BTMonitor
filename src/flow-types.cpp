#include "flow-types.h"
#include "utils.h"
#include "bt-dht-regex.h"
#include "bt-dns-regex.h"
#include "bt-pp-regex.h"

void bidirectional_flow_data::add_packet(const packet_data_t& pkt) {
    if(!packets.empty()){
        if(pkt_pair_timeout_check(packets.back(), pkt)){
            this->output_flow();
            packets.clear();
        }
    }
    packets.push_back(pkt);
}

void bidirectional_flow_data::output_flow() const{
    flow_data_t data{};
    data.src_info = directional_flow_key_t(*packets.begin()); // First packet is the source
    data.pkt_count = packets.size();
    for(auto& pkt : packets){
        data.total_payload += pkt.payload.length();
    }
    data.flow_type = this->analyze_flow();
    data.from = std::chrono::system_clock::to_time_t(packets.front().timestamp);
    data.to = std::chrono::system_clock::to_time_t(packets.back().timestamp);

    ::output_flow(data);
}

bt_type_t bidirectional_flow_data::analyze_flow() const {
    bt_type_t tmp_type;
    bt_type_t type = bt_type_t::UNKNOWN;

    const auto& flow_info_pkt = *packets.begin();

    if(!(program_data.program_flags & program_flags_t::well_defined) &&
        (flow_info_pkt.l4_src < 1024 || flow_info_pkt.l4_dst < 1024) &&
        (flow_info_pkt.l4_src != 53 && flow_info_pkt.l4_dst != 53)){
        return type;
    }

    switch(flow_info_pkt.l4_p){
        case IPPROTO_TCP:
            for(const auto & pkt : packets) {
                if(!(type & bt_type_t::PP_HANDSHAKE) && (tmp_type = pp_regex::match(pkt.payload)) != bt_type_t::UNKNOWN){
                    type |= tmp_type;
                }
            }
            break;
        case IPPROTO_UDP:
            for(const auto & pkt : packets){
                if(pkt.l4_src == 53 || pkt.l4_dst == 53){
                    if((tmp_type = dns_regex::match(pkt.payload)) != bt_type_t::UNKNOWN){
                        type |= tmp_type;
                    }
                    continue;
                }
                if(!(type & bt_type_t::PP_HANDSHAKE) && (tmp_type = pp_regex::match(pkt.payload)) != bt_type_t::UNKNOWN){
                    type |= tmp_type;
                }
                if((tmp_type = dht_regex::match(pkt.payload, type)) != bt_type_t::UNKNOWN){
                    type |= tmp_type;
                }
            }
            break;
    }
    return type;
}
