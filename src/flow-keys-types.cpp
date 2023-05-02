/**
 * Author: Pavel Horáček
 * Nick: xhorac19
 */

#include <functional>
#include "flow-keys-types.h"
#include "utils.h"

std::size_t defined_hash::operator()(const directional_flow_key_t& direct_flow) const{
    std::size_t ip_src_h = std::hash<uint32_t>()(reinterpret_cast<uint32_t>(direct_flow.ip_src.s_addr));
    std::size_t ip_dst_h = std::hash<uint32_t>()(reinterpret_cast<uint32_t>(direct_flow.ip_dst.s_addr));
    std::size_t l4_p_h = std::hash<uint8_t>()(reinterpret_cast<uint8_t>(direct_flow.l4_p));
    std::size_t l4_src_h = std::hash<uint8_t>()(reinterpret_cast<uint16_t>(direct_flow.l4_src));
    std::size_t l4_dst_h = std::hash<uint8_t>()(reinterpret_cast<uint16_t>(direct_flow.l4_dst));

    std::size_t seed = 0;
    hash_combine(seed, ip_src_h);
    hash_combine(seed, ip_dst_h);
    hash_combine(seed, l4_p_h);
    hash_combine(seed, l4_src_h);
    hash_combine(seed, l4_dst_h);

    return seed;
}

std::size_t defined_hash::operator()(const flow_key_t& bidirectional_flow_key) const{
    std::size_t first_h = defined_hash()(bidirectional_flow_key.first);
    std::size_t second_h = defined_hash()(bidirectional_flow_key.second);

    std::size_t seed = 0;
    hash_combine(seed, first_h);
    hash_combine(seed, second_h);

    return seed;
}

directional_flow_key_t::directional_flow_key_t(const in_addr _ip_src,
                                               const in_addr _ip_dst,
                                               const uint8_t _l4_p,
                                               const uint16_t _l4_src,
                                               const uint16_t _l4_dst):
                       ip_src(_ip_src),
                       ip_dst(_ip_dst),
                       l4_p(_l4_p),
                       l4_src(_l4_src),
                       l4_dst(_l4_dst){}

directional_flow_key_t::directional_flow_key_t(const packet_data_t &pkt):
        directional_flow_key_t(pkt.ip_src, pkt.ip_dst, pkt.l4_p, pkt.l4_src, pkt.l4_dst){}


flow_key_t::flow_key_t(const directional_flow_key_t& directional_flow){
    std::size_t directional_flow_h = defined_hash()(directional_flow);

    directional_flow_key_t swaped_flow(directional_flow.ip_dst,
                                       directional_flow.ip_src,
                                       directional_flow.l4_p,
                                       directional_flow.l4_dst,
                                       directional_flow.l4_src);

    std::size_t swaped_flow_h = defined_hash()(swaped_flow);

    if(directional_flow_h > swaped_flow_h){
        first = directional_flow;
        second = swaped_flow;
    }else{
        first = swaped_flow;
        second = directional_flow;
    }
}

flow_key_t::flow_key_t(const packet_data_t& pkt):
        flow_key_t({pkt.ip_src, pkt.ip_dst, pkt.l4_p, pkt.l4_src, pkt.l4_dst}){}
