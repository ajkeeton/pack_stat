#include <string.h>
#include "pack_stat_decode.h"
#include "pack_stat.h"

session_desc_t *http_alloc_ctx() 
{
    return (session_desc_t*)calloc(1, sizeof(session_desc_t));
}

void free_cb(void *h)
{
    delete (session_desc_t*)h;
}

void ps_t::decode_http(const uint8_t *pkt, 
                const uint32_t remaining_pkt_len, 
                packet_t *packet)
{
}

void ps_t::decode_tcp_payload(const uint8_t *pkt, 
                const uint32_t remaining_pkt_len, 
                packet_t *packet)
{
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

    if(ntohs(packet->tcp->src_port) == 80 ||
       ntohs(packet->tcp->dst_port) == 80)
        decode_http(pkt, remaining_pkt_len, packet);
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

    /* Shortcut. Assuming lower port is server instead of decoding handshakes */
    if(ntohs(packet->tcp->src_port) < ntohs(packet->tcp->dst_port))
        stats_global.tcp_server_bytes += packet->tcp_payload_size;
    else
        stats_global.tcp_client_bytes += packet->tcp_payload_size;

    ssnt_key_t key = {
                packet->ipv4->ip_src, packet->ipv4->ip_dst,
                packet->tcp->src_port, packet->tcp->dst_port,
                packet->vlan ? packet->vlan->pri_cfi_vlan : 0 };

    if(!(packet->ssn = (session_desc_t*)ssnt_lookup(ssns, &key))) {
        packet->ssn = new session_desc_t;
        // TODO: check return
        ssnt_insert(ssns, &key, packet->ssn);
    }

    decode_tcp_payload(pkt, remaining_pkt_len, packet);
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

void ps_t::dump()
{
    puts("The epic conclusion:");

    printf("\tTotal packets:        %ld\n", stats_global.total);
    printf("\tTotal bytes:          %ld\n", stats_global.total_bytes);
    puts("");
    printf("\tIPv4:                 %ld\n", stats_global.ipv4);
    printf("\tIPv4 bytes:           %ld\n", stats_global.ipv4_bytes);
    printf("\tIPv6:                 %ld\n", stats_global.ipv6);
    puts("");
    printf("\tTCP:                  %ld\n", stats_global.tcp);
    printf("\tTCP bytes:            %ld\n", stats_global.tcp_bytes);
    printf("\tTCP payload bytes:    %ld\n", stats_global.tcp_payload_bytes);
    printf("\tTCP client bytes:     %ld\n", stats_global.tcp_client_bytes);
    printf("\tTCP server bytes:     %ld\n", stats_global.tcp_server_bytes);
    puts("");
    printf("\tUDP:                  %ld\n", stats_global.udp);
    printf("\tVLAN:                 %ld\n", stats_global.vlan);
    printf("\tARP:                  %ld\n", stats_global.arp);
    printf("\tIPX:                  %ld\n", stats_global.ipx);
    printf("\tIPv4 in IPv4:         %ld\n", stats_global.ip4ip4);
    printf("\tIP Other:             %ld\n", stats_global.other);
    printf("\tIP fragments:         %ld\n", stats_global.ip_frag);
    printf("\tPCAP issue:           %ld\n", stats_global.pcap_file_err);
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
    memset(&stats_global, 0, sizeof(stats_global));
    ssns = ssnt_new_defaults(free_cb);
}
