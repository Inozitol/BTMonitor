#pragma once
#include <regex>
#include "bt-types.h"

namespace pp_regex{

    /// A regular expression that matches against a string inside Peer Protocol header
    /// (see https://www.bittorrent.org/beps/bep_0003.html #peer protocol)
    const std::regex PP_HEADER(R"(\x13BitTorrent protocol)");

    /// Try and match against any Peer Protocol regex
    bt_type_t match(const std::string& payload);
}