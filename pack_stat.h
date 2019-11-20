
#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
#include <stdlib.h>
#include <pcap.h>
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
    PROTO_HTTP,
    PROTO_SSL,
    PROTO_SSH,
    PROTO_OTHER
};

class session_desc_t {
public:
    protocol_t proto;
    uint64_t 
        total_bytes,
        total_client_bytes,
        total_server_bytes,
        total_client_tcp_sync_bytes,
        total_server_tcp_sync_bytes,
        total_client_tcp_payload_bytes,
        total_server_tcp_payload_bytes;
};

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

    session_desc_t *ssn;
};

//map<ssn_key_t, session_desc_t> session_map;

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
        tcp_client_bytes,
        tcp_server_bytes,
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

class ps_t {
    ssnt_t *ssns;
    stats_t stats_global;

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

public:
    ps_t();
    ~ps_t() { ssnt_free(ssns); }
    void dump();
    void add(u_char *user, 
             const struct pcap_pkthdr *pkthdr, 
             const u_char *pkt);
};
