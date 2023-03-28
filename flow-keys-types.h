#pragma once

#include <netinet/in.h>
#include <thread>

#include "packet-types.h"

struct direct_flow_t {
    in_addr ip_src;
    in_addr ip_dst;
    uint8_t l4_p;
    uint16_t l4_src;
    uint16_t l4_dst;

    direct_flow_t() = default;
    direct_flow_t(in_addr ip_src, in_addr ip_dst, uint8_t l4_p, uint16_t l4_src, uint16_t l4_dst);
    explicit direct_flow_t(const packet_data_t& pkt);

    bool operator==(const direct_flow_t& other) const{
        return  this->ip_src.s_addr == other.ip_src.s_addr &&
                this->ip_dst.s_addr == other.ip_dst.s_addr &&
                this->l4_p == other.l4_p &&
                this->l4_src == other.l4_src &&
                this->l4_dst == other.l4_dst;
    }
};

struct bidirectional_flow_key_t{
    direct_flow_t first{};
    direct_flow_t second{};

    bidirectional_flow_key_t() = default;
    explicit bidirectional_flow_key_t(const direct_flow_t&);
    explicit bidirectional_flow_key_t(const packet_data_t&);

    bool operator==(const bidirectional_flow_key_t& other) const{
        return  this->first == other.first && this->second == other.second;
    }
};

struct defined_hash {
    std::size_t operator()(const direct_flow_t& direct_flow) const;
    std::size_t operator()(const bidirectional_flow_key_t& bidirectional_flow_key) const;
};
