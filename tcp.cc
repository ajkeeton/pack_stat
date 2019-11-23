
#include "pack_stat.h"
#include "pack_stat_decode.h"

tcp_seg_t::tcp_seg_t(tcp_t *tcp, uint32_t l) {
    seq = tcp->th_seq;
    ack = tcp->th_ack;
    len = l;
}

tcp_seg_t::tcp_seg_t(uint32_t s, uint32_t a, uint32_t l) {
    seq = s;
    ack = a;
    len = l;
}

void tcp_flow_t::update(packet_t *p) {
    tcp_t *tcp = p->tcp;
    bool in_order = true;

    // XXX Add stat for missing syn
    
    if(in_handshake) {


XXX This only works if the top level keeps track or we this level has the flags


        init_seq = p->tcp->th_seq;
        next_seq = init_seq+1;
        in_handshake = false;
        segs.push_back(tcp_seg_t(p->tcp, 1));
        return;
    }

    // TODO add PAWS

    // XXX Not yet used - only applies if we're popping packets (TODO)
#if 0
    if(!segs.size()) {
        //printf("%u is first (after SYN)\n", tcp->th_seq);
        if(tcp->th_seq == next_seq) {
            next_seq = tcp->th_seq + p->tcp_payload_size;
            segs.push_front(tcp_seg_t(p->tcp, p->tcp_payload_size));
            return;
        }
        // Packet from the past, possible retrans
        else if(tcp->th_seq < next_seq) {
            // XXX TODO
        }
        // Seq > next, we're missing one or more packets
        else {
            // XXX TODO
        }
    }
#endif

    tcp_seg_t seg = tcp_seg_t(tcp, p->tcp_payload_size);
    auto it=segs.end();
    it--;

    // Walk backwards and try to find the node "before" this seg 
    for(; it != segs.begin(); it--) {
        //printf("Current seg: %u, next %u vs new seg: %u \n", it->seq, it->next_seq(), tcp->th_seq);
        //
        if(tcp->th_seq > it->seq)
            break;
        if(tcp->th_seq == it->seq) {
            if(seg == *it) {
                printf("\t%u is a retrans\n", tcp->th_seq);
                it++;
                segs.insert(it, seg);
                stats.retrans++;
                return;
            }
            break;
        }
    }

    // Found it
    if(tcp->th_seq == it->next_seq()) {
        printf("\t%u is in order\n", tcp->th_seq);
        it++;
        
        segs.insert(it, seg);
    }
    // Less than, but missing a segment
    else if(tcp->th_seq < it->next_seq()) {
        // Check for overlapping payload (most likely evasion)
        // (New sequence is greater than old sequence, but the payload is smaller)
        if(tcp->th_seq > it->seq && p->tcp_payload_size) {
            printf("\t%u overlaps!\n", tcp->th_seq);
            // Overlapping packets!
            // XXX TODO stat
            it++;
            segs.insert(it, seg);
            stats.overlaps++;
        }
        else {
            if(tcp->th_seq == it->seq) {
                printf("\t%u has same seg but differs\n", tcp->th_seq);
                it++;
                segs.insert(it, seg);
            } else {
                printf("\t%u is from the past, and we're missing a seg\n", tcp->th_seq);
                segs.insert(it, seg);
                stats.gaps++;
            }
        }
    }
    else {
        // else: tcp->th_seq > it->next_seq()
        printf("\t%u goes in middle or after head\n", tcp->th_seq);
        it++;
        segs.insert(it, seg);
        stats.gaps++;
    }
}

