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
#include "utils.h"

packet_data_t pkt{};

void packet_callback(u_char*, const struct pcap_pkthdr*, const u_char*);

/// SIGINT and SIGTERM are expected ways to exit this program, therefore we need to handle them safely
void signal_handle(int sig){
    std::cout << "\nInterrupt signal [" << sig << "] received." << std::endl;

    if(sig == SIGTERM || sig == SIGINT){
        if(program_data.program_flags & program_flags_t::to_file) {
            std::cout << "Closing file." << std::endl;
            program_data.out_file.close();
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
        }else if(*i == "-o" || *i == "--output"){
            i++;
            if(i == args_vec.end()){
                fprintf(stderr, "Error: Missing output file argument. See --help for more information.\n");
                return -1;
            }
            program_data.out_file.open(*i, std::ios::trunc);
            if(!program_data.out_file.is_open()){
                fprintf(stderr, "Error: file '%s' could not be opened.", &(*i->data()));
                return -1;
            }
            init_csv();
            program_data.program_flags |= program_flags_t::to_file;
        }else if(*i == "-s" || *i == "--to-stdout"){
            program_data.program_flags |= program_flags_t::to_stdout;
        }else if(*i == "-h" || *i == "--help"){
            std::cout << "BitTorrent Monitor\n";
            std::cout << "Output data order:\n";
            std::cout << "\tIP Source | IP Destination | L4 Protocol | L4 Source Port | L4 Destination Port | Packet type\n";
            std::cout << "Options:\n";
            std::cout << "-i [INTERFACE], --interface [INTERFACE]\n\t\tSelect interface to listen on.\n";
            std::cout << "-o [FILE], --output [FILE]\n\t\tWrites gathered packets on lines of selected FILE in csv format.\n";
            std::cout << "-s, --to-stdout\n\t\tOutputs live data into stdout.\n";
            std::cout << std::endl;
            return 0;
        }
    }

    if(!(program_data.program_flags & program_flags_t::to_file) && !(program_data.program_flags & program_flags_t::to_stdout)){
        std::cout << "No output selected. See --help for more information." << std::endl;
        return -1;
    }

    dht_regex::history_clear_start(30);

    pcap_t* handle;
    char err_buffer[PCAP_ERRBUF_SIZE];

    // User picked interface in an argument
    if(program_data.program_flags & program_flags_t::manual_interface) {
        if((handle = pcap_open_live(program_data.interface.data(), 65536, 1, 1000, err_buffer)) == nullptr){
            std::cout << "Unable to open interface " << program_data.interface << "\n";
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

    return 0;
}

void process_tcp(const tcphdr* tcp_hdr, const u_char* packet, uint32_t hdrs_len, uint32_t total_len){
    uint16_t src = ntohs(tcp_hdr->source);
    uint16_t dst = ntohs(tcp_hdr->dest);

    pkt.l4_src = src;
    pkt.l4_dst = dst;

    std::string payload(reinterpret_cast<const char*>(packet+hdrs_len), total_len-hdrs_len);

    pkt.bt_t = bt_type_t::UNKNOWN;

    output_pkt(pkt);
}

void process_udp(const udphdr* udp_hdr, const u_char* packet, uint32_t hdrs_len, uint32_t total_len){
    uint16_t src = ntohs(udp_hdr->source);
    uint16_t dst = ntohs(udp_hdr->dest);

    pkt.l4_src = src;
    pkt.l4_dst = dst;

    std::string payload(reinterpret_cast<const char*>(packet+hdrs_len), total_len-hdrs_len);

    if(src == 53 || dst == 53){
        pkt.bt_t = dns_regex::match(payload);
        goto udp_exit;
    }

    if(src < 1024 || dst < 1024 ){
        pkt.bt_t = bt_type_t::UNKNOWN;
        goto udp_exit;
    }

    pkt.bt_t = dht_regex::match(payload);
    goto udp_exit;

    udp_exit:
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