#include "bt-dns-regex.h"

bt_type_t dns_regex::match(const std::string &payload) {

    if(std::any_of(DNS_BOOTSTRAP_VEC.begin(),
                   DNS_BOOTSTRAP_VEC.end(),
                   [&payload](const std::regex& dns_regex){ return std::regex_search(payload, dns_regex); })){
        return bt_type_t::DNS_BOOTSTRAP;
    }

    if(std::regex_search(payload, DNS_MAINLINE_STATS))
        return bt_type_t::DNS_MAINLINE_STAT;

    if(std::any_of(DNS_MAINLINE.begin(),
                   DNS_MAINLINE.end(),
                   [&payload](const std::regex& dns_regex){ return std::regex_search(payload, dns_regex); })){
        return bt_type_t::DNS_MAINLINE;
    }

    return bt_type_t::UNKNOWN;
}