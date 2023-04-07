#pragma once

#include <cstdint>
#include <type_traits>

enum bt_type_t : int32_t {
    /// Protocol Peer types
    PP_HANDSHAKE =                  1 << 0,

    /// DHT Types
    DHT_QUERY_PING =                1 << 1,
    DHT_QUERY_FIND_NODE =           1 << 2,
    DHT_QUERY_GET_PEERS =           1 << 3,
    DHT_QUERY_ANNOUNCE_PEER =       1 << 4,
    DHT_RESPONSE_PING =             1 << 5,
    DHT_RESPONSE_FIND_NODE =        1 << 6,
    DHT_RESPONSE_GET_PEERS =        1 << 7,
    DHT_RESPONSE_ANNOUNCE_PEER =    1 << 8,

    /// DNS Types
    DNS_BOOTSTRAP =                 1 << 9,
    DNS_MAINLINE_STAT =             1 << 10,
    DNS_MAINLINE =                  1 << 11,

    UNKNOWN =                       1 << 31
};

inline bt_type_t operator| (bt_type_t ls, bt_type_t rs){
    return static_cast<bt_type_t>(static_cast<int32_t>(ls) | static_cast<int32_t>(rs));
}

inline bool operator& (bt_type_t ls, bt_type_t rs){
    return static_cast<bt_type_t>(static_cast<int32_t>(ls) & static_cast<int32_t>(rs)) == rs;
}

inline bt_type_t& operator|=(bt_type_t &ls, bt_type_t rs){
    return ls = static_cast<bt_type_t>(ls | rs);
}