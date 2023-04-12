#pragma once

#include <vector>
#include <string>
#include <regex>

#include "bt-types.h"

namespace dns_regex{

    /// Vector of regular expressions containing a list of bootstrap urls
    const std::vector<std::regex> DNS_BOOTSTRAP_VEC{
        std::regex(R"(\x06router\x0abittorrent\x03com)"),
        std::regex(R"(\x06router\x08utorrent\x03com)"),
        std::regex(R"(\x03dht\x0alibtorrent\x03com)"),
        std::regex(R"(\x03dht\x0etransmissionbt\x03com)"),
        std::regex(R"(\x03dht\x07aelitis\x03com)")
    };

    /// Regular expression matching DNS record of Mainline client statistic collector server
    const std::regex DNS_MAINLINE_STATS(R"([\x03-\x05]i-\d{1,3}[\x03-\x08]b-\d{1,6}\x02bt\x05bench\x08utorrent\x03com)");

    /// Vector of regular expressions matching DNS records of various Mainline specific communication
    const std::vector<std::regex> DNS_MAINLINE{
        std::regex(R"(\x04apps\x0abittorrent\x03com)"),
        std::regex(R"(\x06update\x0abittorrent\x03com)"),
        std::regex(R"(\x03cdn\x02ap\x0abittorrent\x03com)")
    };

    bt_type_t match(const std::string& payload);
}