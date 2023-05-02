#include "utils.h"
#include <ctime>

void init_csv(){
    program_data.out_file << "IP Source,IP Destination,L4 Protocol,L4 Source Port,L4 Destination Port,First Packet Timestamp,Last Packet Timestamp,Total Payload Size,Packet Count,Packet types inside\n";
}

void output_flow(const flow_info_t& info){

    std::time_t first_pkt_time = std::chrono::system_clock::to_time_t(info.first_pkt_time);
    std::time_t last_pkt_time = std::chrono::system_clock::to_time_t(info.last_pkt_time);

    if(program_data.program_flags & program_flags_t::only_bt && info.flow_type == bt_type_t::UNKNOWN)
        return;

    if(program_data.program_flags & program_flags_t::to_file){
        program_data.out_file <<
                              inet_ntoa(info.src_info.ip_src) << ',' <<
                              inet_ntoa(info.src_info.ip_dst) << ',' <<
                              ((info.src_info.l4_p == IPPROTO_UDP) ? ("udp") : ("tcp")) << ',' <<
                              info.src_info.l4_src << ',' <<
                              info.src_info.l4_dst << ',' <<
                              std::put_time(std::localtime(&first_pkt_time), "%F %T") << ',' <<
                              std::put_time(std::localtime(&last_pkt_time), "%F %T") << ',' <<
                              info.total_payload << ',' <<
                              info.pkt_count << ',';

        if(info.flow_type & bt_type_t::PP_HANDSHAKE) {
            program_data.out_file << "PP_HANDSHAKE ";
        }
        if(info.flow_type & bt_type_t::DHT_QUERY_PING) {
            program_data.out_file << "DHT_QUERY_PING ";
        }
        if(info.flow_type & bt_type_t::DHT_QUERY_FIND_NODE) {
            program_data.out_file << "DHT_QUERY_FIND_NODE ";
        }
        if(info.flow_type & bt_type_t::DHT_QUERY_GET_PEERS) {
            program_data.out_file << "DHT_QUERY_GET_PEERS ";
        }
        if(info.flow_type & bt_type_t::DHT_QUERY_ANNOUNCE_PEER) {
            program_data.out_file << "DHT_QUERY_ANNOUNCE_PEER ";
        }
        if(info.flow_type & bt_type_t::DHT_RESPONSE_PING) {
            program_data.out_file << "DHT_RESPONSE_PING ";
        }
        if(info.flow_type & bt_type_t::DHT_RESPONSE_FIND_NODE) {
            program_data.out_file << "DHT_RESPONSE_FIND_NODE ";
        }
        if(info.flow_type & bt_type_t::DHT_RESPONSE_GET_PEERS) {
            program_data.out_file << "DHT_RESPONSE_GET_PEERS ";
        }
        if(info.flow_type & bt_type_t::DHT_RESPONSE_ANNOUNCE_PEER) {
            program_data.out_file << "DHT_RESPONSE_ANNOUNCE_PEER ";
        }
        if(info.flow_type & bt_type_t::DNS_BOOTSTRAP) {
            program_data.out_file << "DNS_BOOTSTRAP ";
        }
        if(info.flow_type & bt_type_t::DNS_MAINLINE_STAT) {
            program_data.out_file << "DNS_MAINLINE_STAT ";
        }
        if(info.flow_type & bt_type_t::DNS_MAINLINE) {
            program_data.out_file << "DNS_MAINLINE ";
        }

        program_data.out_file << '\n';
        program_data.out_file.flush();
    }

    if(program_data.program_flags & program_flags_t::to_stdout){
        std::cout <<
                  std::setw(15) << inet_ntoa(info.src_info.ip_src) << " | " <<
                  std::setw(15) << inet_ntoa(info.src_info.ip_dst) << " | " <<
                  ((info.src_info.l4_p == IPPROTO_UDP) ? ("udp") : ("tcp")) << " | " <<
                  std::setw(5) << info.src_info.l4_src << " | " <<
                  std::setw(5) << info.src_info.l4_dst << " | " <<
                  std::put_time(std::localtime(&first_pkt_time), "%F %T") << " | " <<
                  std::put_time(std::localtime(&last_pkt_time), "%F %T") << " | " <<
                  std::setw(10) << info.total_payload << " | " <<
                  std::setw(5) << info.pkt_count << " | ";

        if(info.flow_type & bt_type_t::PP_HANDSHAKE) {
            std::cout << "PP_HANDSHAKE ";
        }
        if(info.flow_type & bt_type_t::DHT_QUERY_PING) {
            std::cout << "DHT_QUERY_PING ";
        }
        if(info.flow_type & bt_type_t::DHT_QUERY_FIND_NODE) {
            std::cout << "DHT_QUERY_FIND_NODE ";
        }
        if(info.flow_type & bt_type_t::DHT_QUERY_GET_PEERS) {
            std::cout << "DHT_QUERY_GET_PEERS ";
        }
        if(info.flow_type & bt_type_t::DHT_QUERY_ANNOUNCE_PEER) {
            std::cout << "DHT_QUERY_ANNOUNCE_PEER ";
        }
        if(info.flow_type & bt_type_t::DHT_RESPONSE_PING) {
            std::cout << "DHT_RESPONSE_PING ";
        }
        if(info.flow_type & bt_type_t::DHT_RESPONSE_FIND_NODE) {
            std::cout << "DHT_RESPONSE_FIND_NODE ";
        }
        if(info.flow_type & bt_type_t::DHT_RESPONSE_GET_PEERS) {
            std::cout << "DHT_RESPONSE_GET_PEERS ";
        }
        if(info.flow_type & bt_type_t::DHT_RESPONSE_ANNOUNCE_PEER) {
            std::cout << "DHT_RESPONSE_ANNOUNCE_PEER ";
        }
        if(info.flow_type & bt_type_t::DNS_BOOTSTRAP) {
            std::cout << "DNS_BOOTSTRAP ";
        }
        if(info.flow_type & bt_type_t::DNS_MAINLINE_STAT) {
            std::cout << "DNS_MAINLINE_STAT ";
        }
        if(info.flow_type & bt_type_t::DNS_MAINLINE) {
            std::cout << "DNS_MAINLINE ";
        }
        std::cout << std::endl;
    }
}

bool timeout_check(const micro_timepoint& early_ts, const micro_timepoint& late_ts){
    auto diff = late_ts - early_ts;

    if(diff > std::chrono::microseconds(program_data.flow_timeout)){
        return true;
    }
    return false;
}
