#include <netinet/in.h>
#include <arpa/inet.h>
#include "pack_stat_decode.h"
#include "pack_stat.h"

static void free_cb(void *h)
{
    session_desc_t *ssn = (session_desc_t*)h;

    //if(ssn->ps->callbacks.on_session_free)
    //    ssn->ps->callbacks.on_session_free(packet, ssn, callbacks.ctx);

    ssn->ps->add_ssn_stats(ssn); 

    delete ssn;
}

dir_t session_desc_t::get_direction(packet_t *packet) {
    if(!cport && !cip)
        return DIR_UNKNOWN;
    return packet->ipv4->ip_src == cip && 
           packet->tcp->src_port == cport ? IS_CLIENT : IS_SERVER;
}

void session_desc_t::handle_new(packet_t *packet, bool use_client) {
    if(use_client) {
        cip = packet->ipv4->ip_src;
        cport = packet->tcp->src_port;

        dip = packet->ipv4->ip_dst;
        dport = packet->tcp->dst_port;
    } 
    else {
        cip = packet->ipv4->ip_dst;
        cport = packet->tcp->dst_port;

        dip = packet->ipv4->ip_src;
        dport = packet->tcp->src_port;
    }

    client.use_stats(&client_stats);
    server.use_stats(&server_stats);
}

void session_desc_t::update(packet_t *packet) {
    // XXX Revisit - handle endianess in tcp.cc
    packet->tcp->th_seq = ntohl(packet->tcp->th_seq);
    packet->tcp->th_ack = ntohl(packet->tcp->th_ack);
    switch(get_direction(packet)) {
        case IS_CLIENT:
            client.update(packet);
            break;
        case IS_SERVER:
            server.update(packet);
            break;
        default:
            abort();
    }

    update_last = time(NULL);
}

char *session_desc_t::get_description() {
    if(strlen(description))
        return description;

    char srcip[128], dstip[128];
    inet_ntop(AF_INET, (void*)&cip, srcip, sizeof(srcip));
    inet_ntop(AF_INET, (void*)&dip, dstip, sizeof(dstip));
    sprintf(description, "%s:%d <-> %s:%d", srcip, cport, dstip, dport);
    return description;
}

static inline bool has_port(packet_t *packet, uint16_t port) {
    return ntohs(packet->tcp->src_port) == port || 
           ntohs(packet->tcp->dst_port) == port;
}

void ps_t::decode_http(const uint8_t *pkt, 
                const uint32_t remaining_pkt_len, 
                packet_t *packet)
{
    // http_t *http = packet->tcp_payload;
    // Extract something useful?
}

void ps_t::decode_tcp_payload(const uint8_t *pkt, 
                const uint32_t remaining_pkt_len, 
                packet_t *packet)
{
#if 0
    if(!packet->ssn) {
        // XXX This should not have happened
        // error()...
        return;
    }
    //printf("%s\n", key_to_string(packet->tcp_ssn_key));

    /* Check if this packet is shutting down a TCP session */
    if(!packet->tcp_payload_size) {
        if(packet->tcp->th_flags & TH_FIN || 
           packet->tcp->th_flags & TH_RST) {
            // XXX Flag something? No need to delete session, it will 
            // timeout later
            return;
        }
    }

    switch(packet->direction) {
        case IS_CLIENT:
            packet->ssn->total_client_bytes += packet->tcp_payload_size;
            break;
        case IS_SERVER:
            packet->ssn->total_server_bytes += packet->tcp_payload_size;
            break;
        default:
            packet->ssn->total_unknown_dir_bytes += packet->tcp_payload_size;
    }
#endif

    if(has_port(packet, 80)) {
        packet->ssn->proto = PROTO_HTTP;
        decode_http(pkt, remaining_pkt_len, packet);
    }
    else if(has_port(packet, 443)) {
        packet->ssn->proto = PROTO_SSL;
    }
    else if(has_port(packet, 22)) {
        packet->ssn->proto = PROTO_SSH;
    }
    else {
        packet->ssn->proto = PROTO_UNKNOWN;
    }
}

void ps_t::decode_tcp(const uint8_t *pkt, 
                const uint32_t remaining_pkt_len, 
                packet_t *packet)
{
    stats_global.tcp++;
    stats_global.tcp_bytes += remaining_pkt_len;

    uint32_t hlen;            /* TCP header length */

    if(remaining_pkt_len < TCP_HEADER_LEN) {
        puts("TCP packet is too small to fit a header.  Discarding.");
        stats_global.pcap_file_err++;
        return;
    }

    /* lay TCP on top of the data cause there is enough of it! */
    packet->tcp = (tcp_t *)pkt;

    /* multiply the payload offset value by 4 */
    hlen = TCP_OFFSET(packet->tcp) << 2;

    if(hlen < TCP_HEADER_LEN) {
        puts("TCP header length is too small.  Discarding.");
        stats_global.pcap_file_err++;
        return;
    }

    if(hlen > remaining_pkt_len) {
        puts("TCP header length is larger than remaining packet length.  Discarding");
        stats_global.pcap_file_err++;
        return;
    }

    packet->tcp_payload = (uint8_t *)(pkt + hlen);

    if(hlen < remaining_pkt_len)
        packet->tcp_payload_size = (u_short)(remaining_pkt_len - hlen);
    else
        packet->tcp_payload_size = 0;

    stats_global.tcp_payload_bytes += packet->tcp_payload_size;

    bgh_key_t key;
    key.sip = packet->ipv4->ip_src;
    key.dip = packet->ipv4->ip_dst;
    key.sport = packet->tcp->src_port;
    key.dport = packet->tcp->dst_port;
    key.vlan = packet->vlan ? packet->vlan->pri_cfi_vlan : 0;

    if(!(packet->ssn = (session_desc_t*)bgh_lookup(ssns, &key))) {
        packet->ssn = new session_desc_t(this);
        // TODO: check return
        bgh_insert(ssns, &key, packet->ssn);
    }

    session_desc_t *ssn = packet->ssn;

    // Check if new session
    if(packet->tcp->th_flags & TH_SYN) {
        if(!(packet->tcp->th_flags & TH_ACK)) {
            // No ack. This is the client
            
            if(ssn->get_direction(packet) != DIR_UNKNOWN) {
                // we either guessed at the direction earlier or this is a new syn 
                // If direction differs, need to swap flows
                if(ssn->get_direction(packet) == IS_SERVER)
                    ssn->swap_cli_srv();
            }
            else {
                // TODO: Check if already established and tally stat
                ssn->handle_new(packet, true);
            }
        } else {
            // Packet has ack. This is the server
            
            if(ssn->get_direction(packet) != DIR_UNKNOWN) {
                // we either guessed at the direction earlier or this is a new syn/ack
                // If direction differs, need to swap flows
                if(ssn->get_direction(packet) == IS_CLIENT)
                    ssn->swap_cli_srv();
            }
            else {
                // TODO: Check if already established and tally stat
                ssn->handle_new(packet, false);
            }
        }
    }
    else if(ssn->get_direction(packet) == DIR_UNKNOWN) {
        // Guess direction based on ports
        if(packet->tcp->src_port < packet->tcp->dst_port)
            ssn->handle_new(packet, true);
        else
            ssn->handle_new(packet, false);
    }

    ssn->update(packet);
    decode_tcp_payload(pkt, remaining_pkt_len, packet);

    if(callbacks.on_psh && packet->tcp_payload_size) {
        callbacks.on_psh(packet, ssn, callbacks.ctx);
    }

    static time_t now = 0;
    now = time(NULL);

    // Update per second stats only once per second
    if(now - last_update > 1) {
        last_update = now;
        if(callbacks.on_stat_update)
            callbacks.on_stat_update(packet, ssn, callbacks.ctx);

        add_ssn_stats(ssn);
        ssn->clear_stats();
    }
}

void ps_t::decode_udp(const uint8_t *pkt, 
                const uint32_t remaining_pkt_len, 
                packet_t *packet)
{
    stats_global.udp++;
}

void ps_t::decode_ipv4(const uint8_t *pkt, 
                 const uint32_t remaining_pkt_len, 
                 packet_t *packet)
{
    stats_global.ipv4++;
    stats_global.ipv4_bytes += remaining_pkt_len;

    if(remaining_pkt_len < IP_HEADER_LEN) {
        puts("IP header is truncated. Discarding.");
        stats_global.pcap_file_err++;
        return; 
    }  

    packet->ipv4 = (ipv4_t*)pkt;

    if(IP_VER(packet->ipv4) != 4) {
        puts("IPv4 header claims it is not IPv4.");
        stats_global.pcap_file_err++;
        return;
    }

    uint32_t ip_len; /* length from the start of the ip hdr to the pkt end */ 
    uint32_t hlen;   /* ip header length */
   
    /* The IP datagram length */
    ip_len = ntohs(packet->ipv4->ip_len);

    /* The IP header length */
    hlen = IP_HLEN(packet->ipv4) << 2;

    /* header length sanity check */
    if(hlen < IP_HEADER_LEN) {
        puts("IP header is too small.  Discarding");
        stats_global.pcap_file_err++;
        return;
    }

    /* Check if the IP header claims the remaining packet is different than what
       we pulled out of PCAP.  Even if the packet is fragmented, the datagram 
       size should still be correct and consistent. */
    if (ip_len != remaining_pkt_len) {
        if (ip_len > remaining_pkt_len) {
            printf(
                "IP header datagram is longer than PCAP's reported length: "
                "%d > %d.  Discarding.\n", ip_len, remaining_pkt_len);
            stats_global.pcap_file_err++;
            return;
        }
        else {
            /* I'm seeing this occur legitimately when the packet is too small
               for an ethernet frame, and the remaining bytes are padding. */
        }
    }

    /* Verify that the reported IP datagram length is long enough to fit the 
       IP header itself */
    if(ip_len < hlen) {
        puts("IP header datagram length is too short to fit the IP header.  Discarding.");
        stats_global.pcap_file_err++;
        return;
    }

    /* set the remaining packet length */
    ip_len -= hlen;

    /* check for fragmented packets */
    uint16_t frag_offset = ntohs(packet->ipv4->ip_off);
    uint16_t frag_more = (uint8_t)((frag_offset & 0x2000) >> 13);
    frag_offset &= 0x1FFF;

    /* mask off the high bits in the fragment offset field */

    if(frag_offset || frag_more) {
        stats_global.ip_frag++;
        return;
    }

    switch(packet->ipv4->ip_proto)
    {
        case IPPROTO_TCP:
            decode_tcp(pkt + hlen, ip_len, packet);
            return;

        case IPPROTO_UDP:
            decode_udp(pkt + hlen, ip_len, packet);
            return;

        case IPPROTO_IPIP:
            stats_global.ip4ip4++;
            /* Due to the MTU, we don't have to worry about recursing too deep */
            decode_ipv4(pkt + hlen, ip_len, packet);
            return;

        default:
            /* No decoding for these protocols */
            stats_global.other++;
            return;
    }
}

void ps_t::decode_ipv6(const uint8_t *pkt, 
                 const uint32_t remaining_pkt_len, 
                 packet_t *packet)
{
    stats_global.ipv6++;
}

#define LEN_VLAN_LLC_OTHER (sizeof(vlan_t) + sizeof(eth_llc_t) + sizeof(eth_llc_other_t))

void ps_t::decode_vlan(const uint8_t *pkt, 
                 const uint32_t remaining_pkt_len, 
                 packet_t *packet)
{
    stats_global.vlan++;

    if(remaining_pkt_len < VLAN_HEADER_LEN) {
        // puts("802.1Q header is truncated. Discarding.");
        return;
    }  

    packet->vlan = (vlan_t *)pkt;

    // Check to see if there's an encapsulated LLC layer
    // If it's LLC, the type field becomes the lenght which should be less than 1518.
    if(ntohs(packet->vlan->proto) <= ETHERNET_MAX_LEN_ENCAP) {
        stats_global.encapsulated_llc++;

        if(remaining_pkt_len < sizeof(vlan_t) + sizeof(eth_llc_t)) {
            stats_global.proto_err++;
            return;
        }

        packet->eth_llc = (eth_llc_t *)(pkt + sizeof(vlan_t));

        if(packet->eth_llc->dsap == ETH_DSAP_IP && packet->eth_llc->ssap == ETH_SSAP_IP)
        {
            if (remaining_pkt_len < LEN_VLAN_LLC_OTHER)
            {
                stats_global.proto_err++;
                return;
            }

            packet->eth_llc_other = (eth_llc_other_t *)(pkt + sizeof(vlan_t) + sizeof(eth_llc_t));

            switch(ntohs(packet->eth_llc_other->proto_id))
            {
                case ETHERNET_TYPE_IP:
                    decode_ipv4((uint8_t*)packet->pkt + LEN_VLAN_LLC_OTHER,
                             remaining_pkt_len - LEN_VLAN_LLC_OTHER, packet);
                    return;

                case ETHERNET_TYPE_IPV6:
                    decode_ipv6((uint8_t*)packet->pkt + LEN_VLAN_LLC_OTHER,
                               remaining_pkt_len - LEN_VLAN_LLC_OTHER, packet);
                    return;

                case ETHERNET_TYPE_8021Q:
                    //stats_global.nested_vlan++;
                    decode_vlan((uint8_t*)packet->pkt + LEN_VLAN_LLC_OTHER,
                               remaining_pkt_len - LEN_VLAN_LLC_OTHER, packet);
                    return;

                default:
                    // TBD add decoder drop event for unknown vlan/eth type
                    stats_global.other++;
                    return;
            }
        }

        return;
    }

    switch(ntohs(packet->vlan->proto))
    {
        case ETHERNET_TYPE_IP:
            decode_ipv4(pkt + sizeof(vlan_t),
                     remaining_pkt_len - sizeof(vlan_t), packet);
            return;

        case ETHERNET_TYPE_IPV6:
            decode_ipv6(pkt + sizeof(vlan_t),
                       remaining_pkt_len - sizeof(vlan_t), packet);
            return;

        case ETHERNET_TYPE_8021Q:
            decode_vlan(pkt + sizeof(vlan_t),
                       remaining_pkt_len - sizeof(vlan_t), packet);
            return;

        default:
            // TBD add decoder drop event for unknown vlan/eth type
            stats_global.other++;
            return;
    }
}

void ps_t::add(u_char *user, 
             const struct pcap_pkthdr *pkthdr, 
             const u_char *pkt) {
    uint32_t cap_len = pkthdr->caplen;

    if(stats_global.time_start.tv_sec == 0) 
        stats_global.time_start = pkthdr->ts;
    else
        stats_global.time_end = pkthdr->ts;

    stats_global.total++;
    stats_global.total_bytes += pkthdr->len;

    packet_t packet;
    packet.eth = (eth_t*)pkt;
    packet.vlan = NULL;
    packet.pkth = pkthdr; 
    packet.pkt = pkt; 

    /* pkthdr->len is the length of the packet.
       pkthdr->caplen is the length of what was captured, which might be smaller.
        If we're reading from a PCAP file, the packet length should never be 
        smaller than the capture length - unless the file is broken. */
    if(pkthdr->len < cap_len) {
        stats_global.pcap_file_err++;
        puts("Possibly broken PCAP file - packet length less than capture length.");
        return;
    }

    if(pkthdr->caplen < ETHERNET_HEADER_LEN) {
        stats_global.pcap_file_err++;
        puts("Size of captured packet is too small to do anything with.");
        return;
    }

    switch(ntohs(packet.eth->ether_type))
    {
        case ETHERNET_TYPE_IP:
            decode_ipv4(packet.pkt + ETHERNET_HEADER_LEN, 
                       cap_len - ETHERNET_HEADER_LEN, &packet);
            break;

        case ETHERNET_TYPE_ARP:
        case ETHERNET_TYPE_REVARP:
            stats_global.arp++;
            break;

        case ETHERNET_TYPE_IPV6:
            decode_ipv6(packet.pkt + ETHERNET_HEADER_LEN,
                        cap_len - ETHERNET_HEADER_LEN, &packet);
            break;

        case ETHERNET_TYPE_PPPoE_DISC:
            stats_global.pppoe_disc++;
            break;

        case ETHERNET_TYPE_PPPoE_SESS:
            stats_global.pppoe_sess++;
            break;

        case ETHERNET_TYPE_IPX:
            stats_global.ipx++;
            break;

        case ETHERNET_TYPE_LOOP:
            stats_global.loopback++;
            break;

        case ETHERNET_TYPE_8021Q:
            decode_vlan(packet.pkt + ETHERNET_HEADER_LEN,
                         cap_len - ETHERNET_HEADER_LEN, &packet);
            break;

        case ETHERNET_TYPE_MPLS_MULTICAST:
            stats_global.multicast++;
            break;

        case ETHERNET_TYPE_MPLS_UNICAST:
            stats_global.unicast++;
            break;

        default:
            stats_global.other_eth++;
            break;
    }
}

static double time_to_float(struct timeval ts)
{
    double retval = ts.tv_usec;
    retval /= (double)1000000;
    retval += ts.tv_sec;

    return retval;
}

void ps_t::add_ssn_stats(session_desc_t *ssn) {
    tcp_client_stats += ssn->client_stats;
    tcp_server_stats += ssn->server_stats;
}

void ps_t::dump()
{
    puts("The epic conclusion:");

    printf("\tTotal packets:        %llu\n", stats_global.total);
    printf("\tTotal bytes:          %llu\n", stats_global.total_bytes);
    puts("");
    printf("\tIPv4 packets:         %llu\n", stats_global.ipv4);
    printf("\tIPv4 bytes:           %llu\n", stats_global.ipv4_bytes);
    printf("\tIPv6 packets:         %llu\n", stats_global.ipv6);
    puts("");
    printf("\tTCP:                  %llu\n", stats_global.tcp);
    printf("\t   total bytes:       %llu\n", stats_global.tcp_bytes);
    printf("\t   payload bytes:     %llu\n", stats_global.tcp_payload_bytes);
    printf("\t   client bytes:      %lu\n", tcp_client_stats.total);
    printf("\t   server bytes:      %lu\n", tcp_server_stats.total);
    printf("\t   client retrans:    %lu\n", tcp_client_stats.retrans);
    printf("\t   server retrans:    %lu\n", tcp_server_stats.retrans);
    printf("\t   client gaps:       %lu\n", tcp_client_stats.gaps);
    printf("\t   server gaps:       %lu\n", tcp_server_stats.gaps);
    printf("\t   client overlaps:   %llu\n", tcp_client_stats.overlaps);
    printf("\t   server overlaps:   %llu\n", tcp_server_stats.overlaps);
    puts("");
    printf("\tUDP:                  %llu\n", stats_global.udp);
    printf("\tVLAN:                 %llu\n", stats_global.vlan);
    printf("\tARP:                  %llu\n", stats_global.arp);
    printf("\tIPX:                  %llu\n", stats_global.ipx);
    printf("\tIPv4 in IPv4:         %llu\n", stats_global.ip4ip4);
    printf("\tIP Other:             %llu\n", stats_global.other);
    printf("\tIP fragments:         %llu\n", stats_global.ip_frag);
    printf("\tMPLS Multicast:       %llu\n", stats_global.multicast);
    printf("\tMPLS Unicast:         %llu\n", stats_global.unicast);
    printf("\tOther, ignored:       %llu\n", stats_global.other_eth);
    printf("\tPCAP issue:           %llu\n", stats_global.pcap_file_err);
    puts("");
    
    puts("Session cache: ");
    // ssn_tbl_dump();

    double time_span = 
        time_to_float(stats_global.time_end) - time_to_float(stats_global.time_start);

    printf("\tTime span (as reported in pcap): %f\n", time_span);
    printf("\t\t%.2f kilobytes/s (%.2f kilobits/s)\n", 
        stats_global.total_bytes / time_span / 1024,
        stats_global.total_bytes / time_span / 1024 * 8);
}

ps_t::ps_t() {
    init();
}

ps_t::ps_t(const ps_callbacks_t &cb) {
    init();
    callbacks = cb;
}

void ps_t::init() {
    last_update = 0; // time(NULL);
    memset(&stats_global, 0, sizeof(stats_global));
    ssns = bgh_new(free_cb);
}

