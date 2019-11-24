
/* pack_stats */

/* 
Copyright (C) 2009 Adam Keeton <ajkeeton at gmail>
*/

#include <signal.h>
#include <string>
#include <map>
#include <string.h>
#include <unistd.h>
#include <ncurses.h>
#include <map>
using namespace std;
#include "pack_stat.h"
#include "pack_stat_decode.h"

static bool sig_dump_stats = false;

static void free_cb(void *f) { delete (float*)f; }

#define UPDATE_DELAY 100 // ms
class display_t {
    time_t last_update;
    map<float, session_desc_t> ssn_stats;
    ssnt_t *ssns;
public:
    display_t() {
        // init ncurses
//        initscr();
        last_update = 0;
        ssns = ssnt_new_defaults(free_cb);
    }
    ~display_t() {
//        endwin();
        ssnt_free(ssns);
    }
    void update(packet_t *p, session_desc_t *ssn) {
        ssnt_key_t ssn_key = {
                p->ipv4->ip_src, p->ipv4->ip_dst,
                p->tcp->src_port, p->tcp->dst_port,
                p->vlan ? p->vlan->pri_cfi_vlan : 0 };

        float *val = (float*)ssnt_lookup(ssns, &ssn_key);
        if(val) {
            auto it = ssn_stats.find(*val);
            ssn_stats.erase(*val);
        }
        float key = (ssn->client_stats.total + ssn->server_stats.total) / 1024.0;
        ssn_stats[key] = *ssn;
        return;
        if(!val)
            val = new float;
        *val = key;

        ssnt_insert(ssns, &ssn_key, val);
    }

    void draw() {
//        printw("hey");
        // ncurses
        auto it = ssn_stats.end();
        do {
            if(it->first > 0.001) {
                session_desc_t &sd = it->second;
                printf("%s\t%.3f kbs\tretrans: %lu\tgaps: %lu\toverlaps: %lu\n", 
                    sd.get_description(), it->first, 
                    sd.client_stats.retrans + sd.server_stats.retrans, 
                    sd.client_stats.gaps + sd.server_stats.gaps, 
                    sd.client_stats.overlaps + sd.server_stats.overlaps);
            }

            if(it == ssn_stats.begin())
                break;
            it--; 
        } while(true);
        
        puts("==================================\n");
//        refresh();
//        usleep(2000000);
    }
};

// ncurses wrapper
// intentionally global
static display_t display;

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

void on_stat_cb(packet_t *packet, session_desc_t *ssn, void *ctx) {
    display_t *d = (display_t*)ctx;
    d->update(packet, ssn);
    d->draw();
}

void usr1handler(int s) {
    sig_dump_stats = true;
}

int main(int argc, char **argv) 
{
    signal(SIGUSR1, usr1handler);

    char errbuf[PCAP_ERRBUF_SIZE];
    if(argc < 3) {
        usage();
        return -1;
    }

    pcap_t *pcap = NULL;

    bool is_offline = false;
    if(!strcmp(argv[1], "-r")) { 
        if(!(pcap = pcap_open_offline(argv[2], errbuf))) {
            printf("Error opening pcap file: %s\n", errbuf);
            return -1;
        }
        is_offline = true;
    } 
    else if(!strcmp(argv[1], "-i")) { 
        if(!(pcap = pcap_open_live(argv[2], 20000, 1, 100, errbuf))) {
            printf("Error opening NIC %s: %s\n", argv[2], errbuf);
            return -1;
        }
    }

    string bpfstring;

    for(int i=3; i<argc; i++) {
        bpfstring += argv[i];
        bpfstring += " ";
    }

    int datalink = pcap_datalink(pcap);

    if(datalink < 0) {
        printf("Invalid datalink: %s\n", pcap_geterr(pcap));
        return -1;
    }
    else if(datalink != DLT_EN10MB) {
        printf("Wrong datalink: %d\n", datalink);
        return -1;
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

    ps_callbacks_t callbacks;
    callbacks.on_stat_update = on_stat_cb;
    callbacks.ctx = (void*)&display;
    ps_t pcap_stats(callbacks);

    int res = 0;
    while((res = pcap_dispatch(pcap, -1, pcap_cb, (u_char*)&pcap_stats)) >= 0) {
        if(res == 0) { // timeout
            if(sig_dump_stats) {
                sig_dump_stats = false;
                pcap_stats.dump();
            }
            if(is_offline)
                break;
        }
    }

    if(res < 0) {
        printf("Error while looping @ %d: %s\n", __LINE__, pcap_geterr(pcap));
        return -1;
    }

    pcap_stats.dump();

    pcap_close(pcap);

    return 0;
}
