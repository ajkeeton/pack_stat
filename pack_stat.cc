
/* pack_stats */

/* 
Copyright (C) 2009 Adam Keeton <ajkeeton at gmail>
*/

#include <string>
#include <map>
#include <string.h>
using namespace std;
#include "pack_stat.h"

void pcap_cb(u_char *user, 
             const struct pcap_pkthdr *pkthdr, 
             const u_char *pkt)
{
    ps_t *stats = (ps_t*)user;
    stats->add(user, pkthdr, pkt);
}

void usage()
{
    puts("packstats <option> <input> [bpf]\n");
    puts("  -r  Read from pcap");
    puts("  -i  Read from NIC\n");
}

int main(int argc, char **argv) 
{
    char errbuf[PCAP_ERRBUF_SIZE];
    if(argc < 3) {
        usage();
        return -1;
    }

    pcap_t *pcap = NULL;

    if(!strcmp(argv[1], "-r")) { 
        if(!(pcap = pcap_open_offline(argv[2], errbuf))) {
            printf("Error opening pcap file: %s\n", pcap_geterr(pcap));
            return -1;
        }
    } 
    else if(!strcmp(argv[1], "-i")) { 
        if(!(pcap = pcap_create(argv[2], errbuf))) {
            printf("Error opening NIC: %s\n", pcap_geterr(pcap));
            return -1;
        }
    }

    string bpfstring;

    for(int i=3; i<argc; i++) {
        bpfstring += argv[i];
        bpfstring += " ";
    }

    if(bpfstring.size()) {
        printf("Using BPF: %s\n", bpfstring.c_str());

        bpf_u_int32 netmask = 0;
        struct bpf_program bpf;

        if(pcap_compile(pcap, &bpf, bpfstring.c_str(), 0, netmask) < 0) {
            printf("Error compiling BPF \"%s\": %s\n", bpfstring.c_str(), pcap_geterr(pcap));
            return -1;
        }

        if(pcap_setfilter(pcap, &bpf) < 0) {
            printf("Error setting BPF @ %d: %s\n", __LINE__, pcap_geterr(pcap));
            return -1;
        }

        pcap_freecode(&bpf);
    }

    ps_t pcap_stats;

    if(pcap_loop(pcap, -1, pcap_cb, (u_char*)&pcap_stats) == -1) {
        printf("Error while looping @ %d: %s\n", __LINE__, pcap_geterr(pcap));
        return -1;
    }

    pcap_stats.dump();

    return 0;
}
