
#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <list>
#include "ssn_track.h"

struct ssl_t {

};

struct eth_t;
struct vlan_t;
struct eth_llc_t;
struct eth_llc_other_t;
struct ipv4_t;
struct ipv6_t;
struct tcp_t;

enum protocol_t {
    PROTO_UNKNOWN,
    PROTO_HTTP,
    PROTO_SSL,
    PROTO_SSH,
    PROTO_OTHER
};

enum directions_t {
    DIR_UNKNOWN,
    IS_CLIENT,
    IS_SERVER
};

typedef int dir_t;

class tcp_seg_t { 
public:
    uint32_t seq,ack,len;

    tcp_seg_t() {
        seq = ack = len = 0;
    }

    tcp_seg_t(tcp_t *tcp, uint32_t l);

    tcp_seg_t(uint32_t s, uint32_t a, uint32_t l);

    uint32_t next_seq() {
        return seq + len;
    }

    bool operator==(const tcp_seg_t &b) {
        return seq == b.seq && ack == b.ack && len == b.len;
    }
};

class session_desc_t ;
class packet_t {
public:
    const pcap_pkthdr *pkth;
    const uint8_t *pkt;

    eth_t       *eth;
    vlan_t      *vlan;
    eth_llc_t   *eth_llc;
    eth_llc_other_t *eth_llc_other;
    ipv4_t      *ipv4;
    ipv6_t      *ipv6;
    tcp_t       *tcp;
    /* For deeper analysis */
    // http_t      *http;
    // ssl_t       *ssl;

    uint8_t *tcp_payload;
    uint32_t tcp_payload_size;
    dir_t direction;
    session_desc_t *ssn;

    packet_t() { 
        direction = DIR_UNKNOWN;
        tcp_payload_size = 0;
        ssn = NULL; 
    }
};

class tcp_flow_stats_t {
public:
    uint32_t total,
             gaps, 
             overlaps,
             retrans;

    bool missing_syn;

    tcp_flow_stats_t() {
        clear();
    }

    void clear() {
        memset(this, 0, sizeof(tcp_flow_stats_t));
    }

    tcp_flow_stats_t &operator+=(const tcp_flow_stats_t &t) {
        total += t.total;
        gaps += t.gaps;
        overlaps += t.overlaps;
        retrans += t.retrans;
        return *this;
    }
};

class tcp_flow_t {
public:
    bool in_handshake;
    uint32_t init_seq, next_seq;
    tcp_flow_stats_t *stats;
    std::list<tcp_seg_t> segs;

    tcp_flow_t() { 
        in_handshake = true;
        init_seq = next_seq = 0;
    }

    void update(packet_t *packet);

    void use_stats(tcp_flow_stats_t *s) {
        stats = s;
    }
};

class ps_t;
class session_desc_t {
public:
    protocol_t proto;
    /*
    uint64_t 
        // total_bytes,
        total_unknown_dir_bytes,
        total_client_bytes,
        total_server_bytes;
        total_client_tcp_sync_bytes,
        total_server_tcp_sync_bytes,
        total_client_tcp_payload_bytes,
        total_server_tcp_payload_bytes;
    */

    uint32_t cip, dip;
    uint16_t cport, dport;

    tcp_flow_stats_t client_stats, server_stats;
    tcp_flow_t client, server;

    time_t update_first, update_last; // timing/age

    ps_t *ps;
    char description[256];

    session_desc_t() {
        init();
    }

    session_desc_t(ps_t *p) {
        init();
        ps = p;
    }

    void init() {
        cport = dport = 0;
        cip = dip = 0;
        update_first = update_last = time(NULL); 
        proto = PROTO_UNKNOWN;
        description[0] = 0;
    }

    dir_t get_direction(packet_t *packet);
    char *get_description();
    void handle_new(packet_t *packet, bool use_client);
    void update(packet_t *packet);
    void swap_cli_srv() {
        tcp_flow_t tmp = client;
        client = server;
        server = tmp;
    }
    void clear_stats() {
        client_stats.clear();
        server_stats.clear();
    }
};

struct stats_t {
    uint64_t 
        total,
        total_bytes,
        client_sessions,
        server_sessions,
        client_bytes,
        server_bytes,
        unique_sessions,

        port_22,
        port_80,
        port_443,
        other,

        ipv4,
        ipv4_bytes,
        ipv6,
        ip_frag,
        tcp,
        tcp_bytes,
        tcp_payload_bytes,
        udp,
        ip4ip4,
        arp,
        ipx,
        vlan,
        encapsulated_llc,
        loopback,
        pppoe_disc,
        pppoe_sess,
        multicast,
        unicast,
        other_eth,
        proto_err,
        pcap_file_err;

    struct timeval time_start,
        time_end;

    stats_t() { memset(this, 0, sizeof(stats_t)); }
};

class ps_callbacks_t {
public:
    void (*on_stat_update)(packet_t *p, session_desc_t *ssn, void *ctx);
    void (*on_syn)(packet_t *p, session_desc_t *ssn, void *ctx);
    void (*on_fin)(packet_t *p, session_desc_t *ssn, void *ctx);
    void (*on_psh)(packet_t *p, session_desc_t *ssn, void *ctx);
    void *ctx;

    ps_callbacks_t() : on_stat_update(NULL), on_syn(NULL), on_fin(NULL), on_psh(NULL), ctx(NULL) {}
    ps_callbacks_t(void *c) : on_stat_update(NULL), on_syn(NULL), on_fin(NULL), on_psh(NULL), ctx(c) {}
};

class ps_t {
    ssnt_t *ssns;
    stats_t stats_global;
    tcp_flow_stats_t tcp_client_stats, tcp_server_stats;
    ps_callbacks_t callbacks;
    time_t last_update;

    void decode_http(const uint8_t *pkt, 
                const uint32_t remaining_pkt_len, 
                packet_t *packet);

    void decode_tcp_payload(const uint8_t *pkt, 
                const uint32_t remaining_pkt_len, 
                packet_t *packet);

    void decode_tcp(const uint8_t *pkt, 
                const uint32_t remaining_pkt_len, 
                packet_t *packet);

    void decode_udp(const uint8_t *pkt, 
                const uint32_t remaining_pkt_len, 
                packet_t *packet);

    void decode_ipv4(const uint8_t *pkt, 
                 const uint32_t remaining_pkt_len, 
                 packet_t *packet);

    void decode_ipv6(const uint8_t *pkt, 
                 const uint32_t remaining_pkt_len, 
                 packet_t *packet);

    void decode_vlan(const uint8_t *pkt, 
                 const uint32_t remaining_pkt_len, 
                 packet_t *packet);

    void init();
public:
    ps_t();
    ps_t(const ps_callbacks_t &cb);
    ~ps_t() { ssnt_free(ssns); }
    void dump();
    void add(u_char *user, 
             const struct pcap_pkthdr *pkthdr, 
             const u_char *pkt);
    void add_ssn_stats(session_desc_t *s);
};
