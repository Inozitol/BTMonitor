/**
 * Author: Pavel Horáček
 * Nick: xhorac19
 */

#pragma once
#include <regex>
#include "bt-types.h"

namespace pp_regex{

    /**
     * A regular expression that matches against a string inside Peer Protocol header
     * (see https://www.bittorrent.org/beps/bep_0003.html #peer protocol)
     */
    const std::regex PP_HEADER(R"(\x13BitTorrent protocol)");

    /**
     * @brief Function tries to match protocol Peer header regex against the packet payload.
     * @param payload Packet payload
     * @return Type of BitTorrent communication inside the packet
     */
     bt_type_t match(const std::string& payload);
}