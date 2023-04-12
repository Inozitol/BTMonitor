#include "utils.h"

void init_csv(){
    if(program_data.program_flags & program_flags_t::flow_mode) {
        program_data.out_file << "IP Source,IP Destination,L4 Protocol,L4 Source Port,L4 Destination Port,First Packet Timestamp,Last Packet Timestamp,Total Payload Size,Packet Count,Packet types inside\n";
    }else{
        program_data.out_file << "IP Source,IP Destination,L4 Protocol,L4 Source Port,L4 Destination Port,Packet Timestamp,Packet type\n";
    }
}

void output_pkt(const packet_data_t& pkt){
    if(program_data.program_flags & program_flags_t::only_bt && pkt.bt_t == bt_type_t::UNKNOWN)
        return;

    const std::time_t timestamp = std::chrono::system_clock::to_time_t(pkt.timestamp);

    if(program_data.program_flags & program_flags_t::to_file){
        program_data.out_file <<
                              inet_ntoa(pkt.ip_src) << ',' <<
                              inet_ntoa(pkt.ip_dst) << ',' <<
                              ((pkt.l4_p == IPPROTO_UDP) ? ("udp") : ("tcp")) << ',' <<
                              pkt.l4_src << ',' <<
                              pkt.l4_dst << ',' <<
                              std::put_time(std::localtime(&timestamp), "%F %T") << ",";
        switch(pkt.bt_t){
            case bt_type_t::PP_HANDSHAKE:
                program_data.out_file << "PP_HANDSHAKE";
                break;
            case bt_type_t::DHT_QUERY_PING:
                program_data.out_file << "DHT_QUERY_PING";
                break;
            case bt_type_t::DHT_QUERY_FIND_NODE:
                program_data.out_file << "DHT_QUERY_FIND_NODE";
                break;
            case bt_type_t::DHT_QUERY_GET_PEERS:
                program_data.out_file << "DHT_QUERY_GET_PEERS";
                break;
            case bt_type_t::DHT_QUERY_ANNOUNCE_PEER:
                program_data.out_file << "DHT_QUERY_ANNOUNCE_PEER";
                break;
            case bt_type_t::DHT_RESPONSE_PING:
                program_data.out_file << "DHT_RESPONSE_PING";
                break;
            case bt_type_t::DHT_RESPONSE_FIND_NODE:
                program_data.out_file << "DHT_RESPONSE_FIND_NODE";
                break;
            case bt_type_t::DHT_RESPONSE_GET_PEERS:
                program_data.out_file << "DHT_RESPONSE_GET_PEERS";
                break;
            case bt_type_t::DHT_RESPONSE_ANNOUNCE_PEER:
                program_data.out_file << "DHT_RESPONSE_ANNOUNCE_PEER";
                break;
            case bt_type_t::DNS_BOOTSTRAP:
                program_data.out_file << "DNS_BOOTSTRAP";
                break;
            case bt_type_t::DNS_MAINLINE_STAT:
                program_data.out_file << "DNS_MAINLINE_STAT";
                break;
            case bt_type_t::DNS_MAINLINE:
                program_data.out_file << "DNS_MAINLINE";
                break;
            case bt_type_t::UNKNOWN:
                program_data.out_file << "NON_BT";
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
                  std::setw(5) << pkt.l4_dst << " | " <<
                  std::put_time(std::localtime(&timestamp), "%F %T") << " | ";
        switch(pkt.bt_t){
            case bt_type_t::PP_HANDSHAKE:
                std::cout << "PP_HANDSHAKE";
                break;
            case bt_type_t::DHT_QUERY_PING:
                std::cout << "DHT_QUERY_PING";
                break;
            case bt_type_t::DHT_QUERY_FIND_NODE:
                std::cout << "DHT_QUERY_FIND_NODE";
                break;
            case bt_type_t::DHT_QUERY_GET_PEERS:
                std::cout << "DHT_QUERY_GET_PEERS";
                break;
            case bt_type_t::DHT_QUERY_ANNOUNCE_PEER:
                std::cout << "DHT_QUERY_ANNOUNCE_PEER";
                break;
            case bt_type_t::DHT_RESPONSE_PING:
                std::cout << "DHT_RESPONSE_PING";
                break;
            case bt_type_t::DHT_RESPONSE_FIND_NODE:
                std::cout << "DHT_RESPONSE_FIND_NODE";
                break;
            case bt_type_t::DHT_RESPONSE_GET_PEERS:
                std::cout << "DHT_RESPONSE_GET_PEERS";
                break;
            case bt_type_t::DHT_RESPONSE_ANNOUNCE_PEER:
                std::cout << "DHT_RESPONSE_ANNOUNCE_PEER";
                break;
            case bt_type_t::DNS_BOOTSTRAP:
                std::cout << "DNS_BOOTSTRAP";
                break;
            case bt_type_t::DNS_MAINLINE_STAT:
                std::cout << "DNS_MAINLINE_STAT";
                break;
            case bt_type_t::DNS_MAINLINE:
                std::cout << "DNS_MAINLINE";
                break;
            case bt_type_t::UNKNOWN:
                std::cout << "NON_BT";
                break;
        }
        std::cout << std::endl;
    }
}

void output_flow(const flow_data_t& flow){

    if(program_data.program_flags & program_flags_t::only_bt && flow.flow_type == bt_type_t::UNKNOWN)
        return;

    if(program_data.program_flags & program_flags_t::to_file){
        program_data.out_file <<
                              inet_ntoa(flow.src_info.ip_src) << ',' <<
                              inet_ntoa(flow.src_info.ip_dst) << ',' <<
                              ((flow.src_info.l4_p == IPPROTO_UDP) ? ("udp") : ("tcp")) << ',' <<
                              flow.src_info.l4_src << ',' <<
                              flow.src_info.l4_dst << ',' <<
                              std::put_time(std::localtime(&flow.from), "%F %T") << ',' <<
                              std::put_time(std::localtime(&flow.to),   "%F %T") << ',' <<
                              flow.total_payload << ',' <<
                              flow.pkt_count << ',';

        if(flow.flow_type & bt_type_t::PP_HANDSHAKE) {
            program_data.out_file << "PP_HANDSHAKE ";
        }
        if(flow.flow_type & bt_type_t::DHT_QUERY_PING) {
            program_data.out_file << "DHT_QUERY_PING ";
        }
        if(flow.flow_type & bt_type_t::DHT_QUERY_FIND_NODE) {
            program_data.out_file << "DHT_QUERY_FIND_NODE ";
        }
        if(flow.flow_type & bt_type_t::DHT_QUERY_GET_PEERS) {
            program_data.out_file << "DHT_QUERY_GET_PEERS ";
        }
        if(flow.flow_type & bt_type_t::DHT_QUERY_ANNOUNCE_PEER) {
            program_data.out_file << "DHT_QUERY_ANNOUNCE_PEER ";
        }
        if(flow.flow_type & bt_type_t::DHT_RESPONSE_PING) {
            program_data.out_file << "DHT_RESPONSE_PING ";
        }
        if(flow.flow_type & bt_type_t::DHT_RESPONSE_FIND_NODE) {
            program_data.out_file << "DHT_RESPONSE_FIND_NODE ";
        }
        if(flow.flow_type & bt_type_t::DHT_RESPONSE_GET_PEERS) {
            program_data.out_file << "DHT_RESPONSE_GET_PEERS ";
        }
        if(flow.flow_type & bt_type_t::DHT_RESPONSE_ANNOUNCE_PEER) {
            program_data.out_file << "DHT_RESPONSE_ANNOUNCE_PEER ";
        }
        if(flow.flow_type & bt_type_t::DNS_BOOTSTRAP) {
            program_data.out_file << "DNS_BOOTSTRAP ";
        }
        if(flow.flow_type & bt_type_t::DNS_MAINLINE_STAT) {
            program_data.out_file << "DNS_MAINLINE_STAT ";
        }
        if(flow.flow_type & bt_type_t::DNS_MAINLINE) {
            program_data.out_file << "DNS_MAINLINE ";
        }

        program_data.out_file << '\n';
        program_data.out_file.flush();
    }

    if(program_data.program_flags & program_flags_t::to_stdout){
        std::cout <<
                  std::setw(15) << inet_ntoa(flow.src_info.ip_src) << " | " <<
                  std::setw(15) << inet_ntoa(flow.src_info.ip_dst) << " | " <<
                  ((flow.src_info.l4_p == IPPROTO_UDP) ? ("udp") : ("tcp")) << " | " <<
                  std::setw(5) << flow.src_info.l4_src << " | " <<
                  std::setw(5) << flow.src_info.l4_dst << " | " <<
                  std::put_time(std::localtime(&flow.from), "%F %T") << " | " <<
                std::put_time(std::localtime(&flow.to),   "%F %T") << " | " <<
                std::setw(10) << flow.total_payload << " | " <<
                std::setw(5) << flow.pkt_count << " | ";

        if(flow.flow_type & bt_type_t::PP_HANDSHAKE) {
            std::cout << "PP_HANDSHAKE ";
        }
        if(flow.flow_type & bt_type_t::DHT_QUERY_PING) {
            std::cout << "DHT_QUERY_PING ";
        }
        if(flow.flow_type & bt_type_t::DHT_QUERY_FIND_NODE) {
            std::cout << "DHT_QUERY_FIND_NODE ";
        }
        if(flow.flow_type & bt_type_t::DHT_QUERY_GET_PEERS) {
            std::cout << "DHT_QUERY_GET_PEERS ";
        }
        if(flow.flow_type & bt_type_t::DHT_QUERY_ANNOUNCE_PEER) {
            std::cout << "DHT_QUERY_ANNOUNCE_PEER ";
        }
        if(flow.flow_type & bt_type_t::DHT_RESPONSE_PING) {
            std::cout << "DHT_RESPONSE_PING ";
        }
        if(flow.flow_type & bt_type_t::DHT_RESPONSE_FIND_NODE) {
            std::cout << "DHT_RESPONSE_FIND_NODE ";
        }
        if(flow.flow_type & bt_type_t::DHT_RESPONSE_GET_PEERS) {
            std::cout << "DHT_RESPONSE_GET_PEERS ";
        }
        if(flow.flow_type & bt_type_t::DHT_RESPONSE_ANNOUNCE_PEER) {
            std::cout << "DHT_RESPONSE_ANNOUNCE_PEER ";
        }
        if(flow.flow_type & bt_type_t::DNS_BOOTSTRAP) {
            std::cout << "DNS_BOOTSTRAP ";
        }
        if(flow.flow_type & bt_type_t::DNS_MAINLINE_STAT) {
            std::cout << "DNS_MAINLINE_STAT ";
        }
        if(flow.flow_type & bt_type_t::DNS_MAINLINE) {
            std::cout << "DNS_MAINLINE ";
        }
        std::cout << std::endl;
    }
}

bool pkt_pair_timeout_check(const packet_data_t &early_pkt, const packet_data_t &late_pkt) {
    if(timeout_check(early_pkt.timestamp, late_pkt.timestamp)){
        return true;
    }
    return false;
}

bool timeout_check(const micro_timepoint& early_ts, const micro_timepoint& late_ts){
    auto diff = late_ts - early_ts;

    if(diff > std::chrono::microseconds(program_data.flow_timeout)){
        return true;
    }
    return false;
}
