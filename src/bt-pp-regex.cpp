#include "bt-pp-regex.h"

bt_type_t pp_regex::match(const std::string& payload){
    if(std::regex_search(payload, PP_HEADER))
        return bt_type_t::PP_HANDSHAKE;

    return bt_type_t::UNKNOWN;
}