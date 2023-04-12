#pragma once

#include <netinet/in.h>
#include <thread>

#include "packet-types.h"

/** @struct directional_flow_key_t
 * @brief Data holding information for one-way flow
 * @var ip_src Source IP
 * @var ip_dst Destination IP
 * @var l4_p Value found in field 'Protocol' of IP header
 * @var l4_src Source port of transport layer
 * @var l4_dst Destination port of transport layer
 */
struct directional_flow_key_t {
    in_addr ip_src;
    in_addr ip_dst;
    uint8_t l4_p;
    uint16_t l4_src;
    uint16_t l4_dst;

    directional_flow_key_t() = default;
    directional_flow_key_t(in_addr ip_src, in_addr ip_dst, uint8_t l4_p, uint16_t l4_src, uint16_t l4_dst);
    explicit directional_flow_key_t(const packet_data_t& pkt);

    [[maybe_unused]] directional_flow_key_t reverse() const;

    bool operator==(const directional_flow_key_t& other) const{
        return  this->ip_src.s_addr == other.ip_src.s_addr &&
                this->ip_dst.s_addr == other.ip_dst.s_addr &&
                this->l4_p == other.l4_p &&
                this->l4_src == other.l4_src &&
                this->l4_dst == other.l4_dst;
    }
};

/** @struct bidirectional_flow_key_t
 * @brief Data holding information for bidirectional flow used as a key for hash-map
 *
 * This structure can create a flow key from a single packet. It is used as a key generator,
 * directing packets into appropriate flows based on their generated key. It creates same key
 * for packets coming from both ways, therefore it's a bi-directional key tuple.
 *
 * @var first One way flow (from A to B)
 * @var second One way flow (from B to A)
 */
struct bidirectional_flow_key_t{
    directional_flow_key_t first{};
    directional_flow_key_t second{};

    bidirectional_flow_key_t() = default;
    explicit bidirectional_flow_key_t(const directional_flow_key_t&);
    explicit bidirectional_flow_key_t(const packet_data_t&);

    bool operator==(const bidirectional_flow_key_t& other) const{
        return  this->first == other.first && this->second == other.second;
    }
};

/** @struct defined_hash
 * @brief Custom hash used to hash structs directional_flow_key_t and bidirectional_flow_key_t
 */
struct defined_hash {
    std::size_t operator()(const directional_flow_key_t& direct_flow) const;
    std::size_t operator()(const bidirectional_flow_key_t& bidirectional_flow_key) const;
};
