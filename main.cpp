#include <iostream>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <csignal>

#include "bt-dht-regex.h"
#include "bt-dns-regex.h"
#include "bt-pp-regex.h"
#include "flow-analyzer.h"
#include "utils.h"

program_data_t program_data;
packet_data_t pkt{};
thread_killer_t thread_killer;
std::future<void> timeout_task;

void packet_callback(u_char*, const struct pcap_pkthdr*, const u_char*);

/// SIGINT and SIGTERM are expected ways to exit this program, therefore we need to handle them safely
void signal_handle(int sig){
    std::cout << "\nInterrupt signal [" << sig << "] received." << std::endl;

    if(sig == SIGTERM || sig == SIGINT){
        if(program_data.program_flags & program_flags_t::to_file) {
            std::cout << "Closing file." << std::endl;
            program_data.out_file.close();
        }
        if(program_data.program_flags & program_flags_t::flow_mode){
            std::cout << "Waiting for threads to finish." << std::endl;
            thread_killer.kill();
            timeout_task.wait();
        }
    }
    exit(sig);
}

int main(int argc, char* argv[]) {
    signal(SIGTERM, signal_handle);
    signal(SIGINT, signal_handle);

    std::vector<std::string> args_vec(argv+1, argv+argc);

    for(auto i = args_vec.begin(); i != args_vec.end(); ++i){
        if(*i == "-i" || *i == "--interface") {
            i++;
            if(i == args_vec.end()){
                fprintf(stderr, "Error: Missing interface argument. See --help for more information.\n");
                return -1;
            }
            program_data.interface = *i;
            program_data.program_flags = program_data.program_flags | program_flags_t::manual_interface;
        }else if(*i == "-o" || *i == "--output") {
            i++;
            if (i == args_vec.end()) {
                fprintf(stderr, "Error: Missing output file argument. See --help for more information.\n");
                return -1;
            }
            program_data.out_file.open(*i, std::ios::trunc);
            if (!program_data.out_file.is_open()) {
                fprintf(stderr, "Error: file '%s' could not be opened.", &(*i->data()));
                return -1;
            }
            program_data.program_flags |= program_flags_t::to_file;
        }else if(*i == "-p" || *i == "--pcap"){
            i++;
            if(i == args_vec.end()){
                fprintf(stderr, "Error: Missing pcap file argument. See --help for more information.\n");
                return -1;
            }
            program_data.pcap_file = *i;
            program_data.program_flags |= program_flags_t::offline_mode;
        }else if(*i == "-s" || *i == "--to-stdout"){
            program_data.program_flags |= program_flags_t::to_stdout;
        }else if(*i == "-b" || *i == "--only-bt"){
            program_data.program_flags |= program_flags_t::only_bt;
        }else if(*i == "-f" || *i == "--flow-mode"){
            program_data.program_flags |= program_flags_t::flow_mode;
        }else if(*i == "-ft" || *i == "--flow-timeout") {
            i++;
            if (i == args_vec.end()) {
                fprintf(stderr, "Error: Missing time argument in --flow-timeout. See --help for more information.\n");
                return -1;
            }
            program_data.flow_timeout = std::stoi(*i);
        }else if(*i == "-fw" || *i == "--flow-wait") {
            i++;
            if (i == args_vec.end()) {
                fprintf(stderr, "Error: Missing time argument in --flow-wait. See --help for more information.\n");
                return -1;
            }
            program_data.flow_wait = std::stoi(*i);
        }else if(*i == "-wd" || *i == "--well-defined"){
            program_data.program_flags |= program_flags_t::well_defined;
        }else if(*i == "-h" || *i == "--help"){
            std::cout << "BitTorrent Monitor\n";
            std::cout << "Output data order:\n";
            std::cout << "Packet mode:\n";
            std::cout << "\tIP Source | IP Destination | L4 Protocol | L4 Source Port | L4 Destination Port | Packet Timestamp | Packet type\n";
            std::cout << "Flow mode:\n";
            std::cout << "\tIP Source | IP Destination | L4 Protocol | L4 Source Port | L4 Destination Port | First Packet Timestamp | Last Packet Timestamp | Total Payload Size | Packet Count | Packet types inside\n";
            std::cout << "Options:\n";
            std::cout << "-i [INTERFACE], --interface [INTERFACE]\n\t\tSelect interface to listen on.\n";
            std::cout << "-o [FILE], --output [FILE]\n\t\tWrites gathered packets on lines of selected FILE in csv format.\n";
            std::cout << "-p [FILE], --pcap [FILE]\n\t\tUses a pcap file as input, instead of live monitoring.\n";
            std::cout << "-s, --to-stdout\n\t\tOutputs live data into stdout.\n";
            std::cout << "-b, --only-bt\n\t\tOutputs only packets attributed to BitTorrent traffic.\n";
            std::cout << "-f, --flow-mode\n\t\tAnalyzes traffic based on bidirectional flows between IPs and ports.\n";
            std::cout << "-ft [MICROSECONDS], --flow-timeout [MICROSECONDS]\n\t\tSets the timeout timespan for flows. Default value is 1000000.\n";
            std::cout << "-fw [SECONDS], --flow-wait [SECONDS]\n\t\tLive monitoring in flow mode runs a secondary thread to check for timed out flows.\n";
            std::cout << "\t\tThis option defines the period in seconds on which this thread will check for those flows.\n";
            std::cout << "-wd, --well-defined\n\t\tAllows the monitoring of well-defined ports (ports over below 1024). This is used to slightly increase precision over performance.\n";
            std::cout << std::endl;
            return 0;
        }
    }

    if(program_data.out_file.is_open()){
        init_csv();
    }

    // User didn't select any output
    if(!(program_data.program_flags & program_flags_t::to_file) && !(program_data.program_flags & program_flags_t::to_stdout)){
        fprintf(stderr,"No output selected. See --help for more information.\n");

        return -1;
    }

    // User selected both interface and pcap file input. Pcap file has priority over live monitoring.
    if((program_data.program_flags & program_flags_t::offline_mode) && (program_data.program_flags & program_flags_t::manual_interface)){
        fprintf(stderr,"Interface selected in offline mode. Ignoring interface argument.\n");
    }

    if((program_data.program_flags & program_flags_t::flow_mode) && !(program_data.program_flags & program_flags_t::offline_mode) ) {
        flow_analyzer::timeout_clear_start(program_data.flow_wait);     // Starting periodically started thread to check flow timeouts
    }else if(!(program_data.program_flags & program_flags_t::flow_mode)){
        dht_regex::history_clear_start(30);     // Starting periodically started thread to clean old DHT memory
    }

    pcap_t* handle;
    char err_buffer[PCAP_ERRBUF_SIZE];

    if(program_data.program_flags & program_flags_t::offline_mode){                 // User picked pcap file as input
        if((handle = pcap_open_offline(program_data.pcap_file.data(), err_buffer)) == nullptr){
            fprintf(stderr,"Unable to open pcap file %s \n", program_data.pcap_file.data());
            fprintf(stderr, "%s\n", err_buffer);
            return -1;
        }
    }else if(program_data.program_flags & program_flags_t::manual_interface) {      // User picked interface in an argument
        if((handle = pcap_open_live(program_data.interface.data(), 65536, 1, 1000, err_buffer)) == nullptr){
            fprintf(stderr,"Unable to open open interface %s \n", program_data.interface.data());
            fprintf(stderr, "%s\n",err_buffer);
            return -1;
        }
    }else{ // User has to pick interface manually
        pcap_if_t* devs = nullptr;

        if (pcap_findalldevs(&devs, err_buffer) < 0) {
            fprintf(stderr, "Can't get the list of interfaces\n");
            return -1;
        }
        pcap_if_t *it;
        int i = 0;
        for (it = devs; it; it = it->next) {
            std::cout << ++i << " - " << it->name << " | ";
            if (it->description) {
                std::cout << it->description;
            } else {
                std::cout << "unknown description";
            }
            std::cout << std::endl;
        }
        pcap_freealldevs(devs);

        if (i == 0) {
            fprintf(stderr, "Didn't find any devices\n");
            return -1;
        }

        sel_interface:

        std::string if_name;
        std::cout << "Select interface by name: ";
        std::cin >> if_name;

        if((handle = pcap_open_live(if_name.data(), 65536, 1, 1000, err_buffer)) == nullptr){
            std::cout << "Unable to open interface " << if_name << "\n";
            fprintf(stderr, "%s\n",err_buffer);
            goto sel_interface;
        }
    }

    pcap_loop(handle, 0, packet_callback, nullptr);
    pcap_close(handle);

    if(program_data.program_flags & program_flags_t::flow_mode){
        if(program_data.program_flags & program_flags_t::offline_mode){
            for(auto& flow : flow_analyzer::flow_table){
                flow.second.output_flow();
            }
        }else {
            thread_killer.kill();
            timeout_task.wait();
        }
    }

    return 0;
}

void process_tcp(const tcphdr* tcp_hdr, const u_char* packet, uint32_t hdrs_len, uint32_t total_len){
    uint16_t src = ntohs(tcp_hdr->source);
    uint16_t dst = ntohs(tcp_hdr->dest);

    pkt.l4_src = src;
    pkt.l4_dst = dst;

    std::string payload(reinterpret_cast<const char*>(packet+hdrs_len), total_len-hdrs_len);

    if(program_data.program_flags & program_flags_t::flow_mode){
        pkt.payload = payload;
        flow_analyzer::process_pkt(pkt); return;
    }

    if(!(program_data.program_flags & program_flags_t::well_defined) && (src < 1024 || dst < 1024 )){
        pkt.bt_t = bt_type_t::UNKNOWN;
        output_pkt(pkt); return;
    }

    pkt.bt_t = pp_regex::match(payload);
    output_pkt(pkt);
}

void process_udp(const udphdr* udp_hdr, const u_char* packet, uint32_t hdrs_len, uint32_t total_len){
    uint16_t src = ntohs(udp_hdr->source);
    uint16_t dst = ntohs(udp_hdr->dest);

    pkt.l4_src = src;
    pkt.l4_dst = dst;

    std::string payload(reinterpret_cast<const char*>(packet+hdrs_len), total_len-hdrs_len);

    if(program_data.program_flags & program_flags_t::flow_mode){
        pkt.payload = payload;
        flow_analyzer::process_pkt(pkt);
        return;
    }

    if(src == 53 || dst == 53){
        pkt.bt_t = dns_regex::match(payload);
        output_pkt(pkt); return;
    }

    if(!(program_data.program_flags & program_flags_t::well_defined) && (src < 1024 || dst < 1024)){
        pkt.bt_t = bt_type_t::UNKNOWN;
        output_pkt(pkt); return;
    }

    if((pkt.bt_t = dht_regex::match(payload)) != bt_type_t::UNKNOWN) {
        output_pkt(pkt); return;
    }

    if((pkt.bt_t = pp_regex::match(payload)) != bt_type_t::UNKNOWN) {
        output_pkt(pkt); return;
    }

    output_pkt(pkt);
}

void packet_callback(u_char*, const struct pcap_pkthdr *header, const u_char* packet){
    ether_header* eth_hdr;
    ip* ip_hdr;
    tcphdr* tcp_hdr;
    udphdr* udp_hdr;
    uint32_t total_len = header->caplen;
    uint32_t ether_len = 14;
    uint32_t ip_len;
    uint32_t l4_len;

    if(header->len < sizeof(struct ether_header))
        return;

    eth_hdr = (ether_header*)packet;
    if(ntohs(eth_hdr->ether_type) != ETHERTYPE_IP)
        return;

    ip_hdr = (ip*)(packet + sizeof(struct ether_header));
    ip_len = ip_hdr->ip_hl*4;

    pkt.timestamp = timeval2timepoint(header->ts);
    pkt.ip_src = ip_hdr->ip_src;
    pkt.ip_dst = ip_hdr->ip_dst;
    pkt.l4_p   = ip_hdr->ip_p;

    switch(ip_hdr->ip_p){
        case IPPROTO_TCP:
            tcp_hdr = (struct tcphdr*)(packet + ether_len + ip_len);
            l4_len = tcp_hdr->th_off * 4;
            process_tcp(tcp_hdr, packet, (ether_len + ip_len + l4_len), total_len);
            break;

        case IPPROTO_UDP:
            udp_hdr = (struct udphdr*)(packet + ether_len + ip_len);
            l4_len = 8;

            process_udp(udp_hdr, packet, (ether_len + ip_len + l4_len), total_len);
            break;
    }

}
