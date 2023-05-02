
#include "pkt-analyzer.h"
#include "utils.h"

bt_type_t analyze_packet(const packet_data_t& pkt){
    switch(pkt.l4_p){
        case IPPROTO_TCP:
            if((pkt.l4_src >= 1024 && pkt.l4_dst >= 1024) ||
                program_data.program_flags & well_defined){
                return pp_regex::match(pkt.payload);
            }
            break;
        case IPPROTO_UDP:
            if((pkt.l4_src >= 1024 && pkt.l4_dst >= 1024) ||
               program_data.program_flags & well_defined){
                bt_type_t type = pp_regex::match(pkt.payload);
                if(type != bt_type_t::UNKNOWN){
                    return type;
                }
                return dht_regex::match(pkt.payload);
            }else if((pkt.l4_src == 53 || pkt.l4_dst == 53)){
                return dns_regex::match(pkt.payload);
            }
            break;
        default:
            return bt_type_t::UNKNOWN;
    }
    return bt_type_t::UNKNOWN;
}