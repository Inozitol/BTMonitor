#pragma once

#include <netinet/in.h>
#include <thread>

#include "packet-types.h"

/**
 * @struct directional_flow_key_t
 * @brief Data holding information for one-way flow
 */
struct directional_flow_key_t {
    in_addr ip_src;         ///< Source IP
    in_addr ip_dst;         ///< Destination IP
    uint8_t l4_p;           ///< Layer 4 Protocol
    uint16_t l4_src;        ///< Layer 4 Source Port
    uint16_t l4_dst;        ///< Layer 4 Destination Port

    /**
     * @brief Default copy constructor
     */
    directional_flow_key_t() = default;

    /**
     * @brief Creates structure from input parameters
     *
     * @param ip_src Source IP
     * @param ip_dst Destination IP
     * @param l4_p Layer 4 Protocol
     * @param l4_src Layer 4 Source Port
     * @param l4_dst Layer 4 Destination Port
     */
    directional_flow_key_t(in_addr ip_src, in_addr ip_dst, uint8_t l4_p, uint16_t l4_src, uint16_t l4_dst);

    /**
     * @brief Creates structure from a single packet information
     *
     * @param pkt Packet
     */
    explicit directional_flow_key_t(const packet_data_t& pkt);

    /**
     * @brief Compares two structures to be equivalent
     *
     * @param other Other directional flow key
     */
    bool operator==(const directional_flow_key_t& other) const{
        return  this->ip_src.s_addr == other.ip_src.s_addr &&
                this->ip_dst.s_addr == other.ip_dst.s_addr &&
                this->l4_p == other.l4_p &&
                this->l4_src == other.l4_src &&
                this->l4_dst == other.l4_dst;
    }
};

/**
 * @struct flow_key_t
 * @brief Data holding information for bidirectional flow used as a key for hash-map
 *
 * This structure can create a flow key from a single packet. It is used as a key generator,
 * directing packets into appropriate flows based on their generated key. It creates same key
 * for packets coming from both ways, therefore it's a bi-directional key.
 */
struct flow_key_t{
    directional_flow_key_t first{};     ///< One way flow (from A to B)
    directional_flow_key_t second{};    ///< One way flow (from B to A)

    flow_key_t() = default;

    /**
     * @brief Creates structure from one directional flow
     *
     * @param dir_flow Directional flow
     */
    explicit flow_key_t(const directional_flow_key_t& dir_flow);

    /**
     * @brief Creates structure from one packet
     *
     * @param pkt Packet
     */
    explicit flow_key_t(const packet_data_t& pkt);

    /**
     * @brief Compares two structures to be equivalent
     *
     * @param other Other flow key
     */
    bool operator==(const flow_key_t& other) const{
        return  this->first == other.first && this->second == other.second;
    }
};

/**
 * @struct defined_hash
 * @brief Custom hash used to hash structs directional_flow_key_t and flow_key_t
 */
struct defined_hash {
    /**
     * @brief Returns hash for directional_flow_key_t
     *
     * @param direct_flow Directional flow key
     */
    std::size_t operator()(const directional_flow_key_t& direct_flow) const;

    /**
     * @brief Returns hash for flow_key_t
     *
     * @param bidirectional_flow_key Bidirectional flow key
     */
    std::size_t operator()(const flow_key_t& bidirectional_flow_key) const;
};
