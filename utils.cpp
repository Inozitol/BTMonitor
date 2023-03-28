#include "utils.h"

void init_csv(){
    if(program_data.program_flags & program_flags_t::flow_mode) {
        program_data.out_file << "IP 1,IP 2,L4 Protocol,L4 Port 1,L4 Port 2,First Packet Timestamp,Last Packet Timestamp,Total Payload Size,Packet Count,Packet type\n";
    }else{
        program_data.out_file << "IP Source,IP Destination,L4 Protocol,L4 Source Port,L4 Destination Port,Packet Timestamp,Packet type\n";
    }
}

void output_pkt(const packet_data_t& pkt){
    if(program_data.program_flags & program_flags_t::only_bt && pkt.bt_t == bt_type_t::UNKNOWN)
        return;

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
        // TODO Print time
        //std::put_time(std::localtime(std::chrono::system_clock::to_time_t(pkt.ts)), "%F %T");
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

void output_flow(const flow_data_t& flow){
    static std::mutex mtx;

    mtx.lock();
    if(program_data.program_flags & program_flags_t::only_bt && flow.flow_type == bt_type_t::UNKNOWN)
        return;

    if(program_data.program_flags & program_flags_t::to_file){
        program_data.out_file <<
                              inet_ntoa(flow.header_info.ip_src) << ',' <<
                              inet_ntoa(flow.header_info.ip_dst) << ',' <<
                              ((flow.header_info.l4_p == IPPROTO_UDP) ? ("udp") : ("tcp")) << ',' <<
                              flow.header_info.l4_src << ',' <<
                              flow.header_info.l4_dst << ',' <<
                              std::put_time(std::localtime(&flow.from), "%F %T") << ',' <<
                              std::put_time(std::localtime(&flow.to),   "%F %T") << ',' <<
                              flow.total_payload << ',' <<
                              flow.pkt_count << ',';

        switch(flow.flow_type){
            case bt_type_t::UNKNOWN:
                program_data.out_file << "non_bt_flow";
                break;

            case bt_type_t::QUERY_PING:
            case bt_type_t::QUERY_FIND_NODE:
            case bt_type_t::QUERY_GET_PEERS:
            case bt_type_t::QUERY_ANNOUNCE_PEER:
            case bt_type_t::RESPONSE_PING:
            case bt_type_t::RESPONSE_FIND_NODE:
            case bt_type_t::RESPONSE_GET_PEERS:
            case bt_type_t::RESPONSE_ANNOUNCE_PEER:
            case bt_type_t::DNS_BOOTSTRAP:
            case bt_type_t::DNS_MAINLINE_STAT:
            case bt_type_t::DNS_MAINLINE:
                break;
        }
        program_data.out_file << '\n';
        program_data.out_file.flush();
    }

    if(program_data.program_flags & program_flags_t::to_stdout){
        std::cout <<
                std::setw(15) << inet_ntoa(flow.header_info.ip_src) << " | " <<
                std::setw(15) << inet_ntoa(flow.header_info.ip_dst) << " | " <<
                ((flow.header_info.l4_p == IPPROTO_UDP) ? ("udp") : ("tcp")) << " | " <<
                std::setw(5) << flow.header_info.l4_src << " | " <<
                std::setw(5) << flow.header_info.l4_dst << " | " <<
                std::put_time(std::localtime(&flow.from), "%F %T") << " | " <<
                std::put_time(std::localtime(&flow.to),   "%F %T") << " | " <<
                flow.total_payload << " | " <<
                flow.pkt_count << " | ";

        switch(flow.flow_type){
            case bt_type_t::UNKNOWN:
                std::cout << "non_bt_flow";
                break;

            case bt_type_t::QUERY_PING:
            case bt_type_t::QUERY_FIND_NODE:
            case bt_type_t::QUERY_GET_PEERS:
            case bt_type_t::QUERY_ANNOUNCE_PEER:
            case bt_type_t::RESPONSE_PING:
            case bt_type_t::RESPONSE_FIND_NODE:
            case bt_type_t::RESPONSE_GET_PEERS:
            case bt_type_t::RESPONSE_ANNOUNCE_PEER:
            case bt_type_t::DNS_BOOTSTRAP:
            case bt_type_t::DNS_MAINLINE_STAT:
            case bt_type_t::DNS_MAINLINE:
                break;
        }
        std::cout << std::endl;
    }
    mtx.unlock();

}

bool pkt_pair_timeout_check(const packet_data_t &early_pkt, const packet_data_t &late_pkt) {
    if(timeout_check(early_pkt.ts, late_pkt.ts)){
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