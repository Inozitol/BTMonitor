#pragma once

#include <netinet/ip.h>
#include <fstream>
#include <iomanip>
#include "bt-types.h"

enum program_flags_t : u_int8_t {
    manual_interface = 0b0001,
    to_file          = 0b0010,
    to_stdout        = 0b0100
};

inline program_flags_t operator|(program_flags_t ls, program_flags_t rs){
    return static_cast<program_flags_t>(static_cast<u_int8_t>(ls) | static_cast<u_int8_t>(rs));
}

inline program_flags_t operator&(program_flags_t ls, program_flags_t rs){
    return static_cast<program_flags_t>(static_cast<u_int8_t>(ls) & static_cast<u_int8_t>(rs));
}

inline program_flags_t& operator|=(program_flags_t &ls, program_flags_t rs){
    return ls = static_cast<program_flags_t>(ls | rs);
}

struct program_data_t{
    std::string interface;
    std::ofstream out_file;
    program_flags_t program_flags{};
};

struct packet_data_t {
    in_addr ip_src;
    in_addr ip_dst;
    u_char l4_p;
    u_short l4_src;
    u_short l4_dst;
    bt_type_t bt_t;
};

static program_data_t program_data;

void init_csv(){
    program_data.out_file << "IP Source,IP Destination,L4 Protocol,L4 Source Port,L4 Destination Port,Packet type\n";
}

void output_pkt(const packet_data_t& pkt){

    if(program_data.program_flags & program_flags_t::to_file){
        program_data.out_file <<
        inet_ntoa(pkt.ip_src) << ',' <<
        inet_ntoa(pkt.ip_dst) << ',' <<
        ((pkt.l4_p == IPPROTO_UDP) ? ("udp") : ("tcp")) << ',' <<
        pkt.l4_src << ',' <<
        pkt.l4_dst << ',';
        switch(pkt.bt_t){

            case bt_type_t::QUERY_PING:
                program_data.out_file << "bittorrent_dht_query_ping";
                break;
            case bt_type_t::QUERY_FIND_NODE:
                program_data.out_file << "bittorrent_dht_query_find_node";
                break;
            case bt_type_t::QUERY_GET_PEERS:
                program_data.out_file << "bittorrent_dht_query_get_peers";
                break;
            case bt_type_t::QUERY_ANNOUNCE_PEER:
                program_data.out_file << "bittorrent_dht_query_announce_peers";
                break;
            case bt_type_t::RESPONSE_PING:
                program_data.out_file << "bittorrent_dht_response_ping";
                break;
            case bt_type_t::RESPONSE_FIND_NODE:
                program_data.out_file << "bittorrent_dht_response_find_node";
                break;
            case bt_type_t::RESPONSE_GET_PEERS:
                program_data.out_file << "bittorrent_dht_response_get_peers";
                break;
            case bt_type_t::RESPONSE_ANNOUNCE_PEER:
                program_data.out_file << "bittorrent_dht_response_announce_peer";
                break;
            case bt_type_t::DNS_BOOTSTRAP:
                program_data.out_file << "bittorrent_dns_bootstrap";
                break;
            case bt_type_t::DNS_MAINLINE_STAT:
                program_data.out_file << "bittorent_dns_mainline_stats";
                break;
            case bt_type_t::DNS_MAINLINE:
                program_data.out_file << "bittorent_dns_mainline";
                break;
            case bt_type_t::UNKNOWN:
                program_data.out_file << "non_bt";
                break;
        }
        program_data.out_file << '\n';
        program_data.out_file.flush();
    }

    if(program_data.program_flags & program_flags_t::to_stdout){
        std::cout <<
        std::setw(15) << inet_ntoa(pkt.ip_src) << " | " <<
        std::setw(15) << inet_ntoa(pkt.ip_dst) << " | " <<
        ((pkt.l4_p == IPPROTO_UDP) ? ("udp") : ("tcp")) << " | " <<
        std::setw(5) << pkt.l4_src << " | " <<
        std::setw(5) << pkt.l4_dst << " | ";
        switch(pkt.bt_t){
            case bt_type_t::QUERY_PING:
                std::cout << "bittorrent_dht_query_ping";
                break;
            case bt_type_t::QUERY_FIND_NODE:
                std::cout << "bittorrent_dht_query_find_node";
                break;
            case bt_type_t::QUERY_GET_PEERS:
                std::cout << "bittorrent_dht_query_get_peers";
                break;
            case bt_type_t::QUERY_ANNOUNCE_PEER:
                std::cout << "bittorrent_dht_query_announce_peers";
                break;
            case bt_type_t::RESPONSE_PING:
                std::cout << "bittorrent_dht_response_ping";
                break;
            case bt_type_t::RESPONSE_FIND_NODE:
                std::cout << "bittorrent_dht_response_find_node";
                break;
            case bt_type_t::RESPONSE_GET_PEERS:
                std::cout << "bittorrent_dht_response_get_peers";
                break;
            case bt_type_t::RESPONSE_ANNOUNCE_PEER:
                std::cout << "bittorrent_dht_response_announce_peer";
                break;
            case bt_type_t::DNS_BOOTSTRAP:
                std::cout << "bittorrent_dns_bootstrap";
                break;
            case bt_type_t::DNS_MAINLINE_STAT:
                std::cout << "bittorent_dns_mainline_stats";
                break;
            case bt_type_t::DNS_MAINLINE:
                std::cout << "bittorent_dns_mainline";
                break;
            case bt_type_t::UNKNOWN:
                std::cout << "non_bt";
                break;
        }
        std::cout << std::endl;
    }
}