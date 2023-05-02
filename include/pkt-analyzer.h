#pragma once

#include "bt-pp-regex.h"
#include "bt-dht-regex.h"
#include "bt-dns-regex.h"
#include "bt-types.h"
#include "packet-types.h"

/**
 * @brief Function that calls appropriate match functions based on the header info from packet
 * @param pkt Packet to analyze
 * @return Type of BitTorrent communication inside the packet
 */
bt_type_t analyze_packet(const packet_data_t& pkt);