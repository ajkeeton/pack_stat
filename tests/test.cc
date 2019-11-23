#include <assert.h>
#include <stdio.h>
#include <map>
#include "pack_stat.h"
#include "pack_stat_decode.h"

class test_tcp_seg_t {
    tcp_flow_t *tcp;
    tcp_seg_t *current;
    test_tcp_seg_t();
public:
    test_tcp_seg_t(tcp_flow_t &t) {
        tcp = &t;
        current = NULL;
    }

    test_tcp_seg_t &node(int node_num) {
        for(auto it = tcp->segs.begin(); it != tcp->segs.end(); it++) {
            if(node_num-- == 0) {
                current = &*it;
                return *this;
            }
        }

        current = NULL;
        return *this;
    }

    test_tcp_seg_t &has_seq(int s) {
        assert(current && current->seq == s);
        return *this;
    }

    test_tcp_seg_t &has_length(int l) {
        assert(current && current->len == l);
        return *this;
    }
};

void print_seg(tcp_seg_t &seg) {
    printf("Seg: %u %u %u\n", seg.seq, seg.ack, seg.len);
}

void print_segs(tcp_flow_t &tcp) {
    puts("Current segs:");
    for(auto it=tcp.segs.begin(); it != tcp.segs.end(); it++)
        print_seg(*it);
    puts("");
}

void init_tcp_test(tcp_flow_t &tcp, packet_t &pack, tcp_t &tcph) {
    memset(&tcph, 0, sizeof(tcph));
    memset(&pack, 0, sizeof(pack));
    pack.tcp = &tcph;
    tcph.th_seq = 1;
    tcph.th_ack = 1000;
    tcp.update(&pack);
}

#define TCP_TEST_SETUP \
    printf("%s\n", __func__); \
    tcp_flow_t tcp; \
    packet_t pack; \
    tcp_t tcph; \
    init_tcp_test(tcp, pack, tcph); \
    tcph.th_seq++; \
    test_tcp_seg_t test(tcp);

void tcp_basic() {
    TCP_TEST_SETUP

    assert(tcp.segs.size() == 1);
    assert(tcp.segs.begin()->next_seq() == 2);

    assert(!tcp.stats.gaps && !tcp.stats.overlaps && !tcp.stats.retrans);
}

void tcp_forward() {
    TCP_TEST_SETUP

    pack.tcp_payload_size = 5;
    tcp.update(&pack);
    test.node(1).has_seq(2).has_length(5);
    tcph.th_seq = 7;

    pack.tcp_payload_size = 0;
    tcp.update(&pack);
    test.node(2).has_seq(7).has_length(0);
    tcph.th_seq += pack.tcp_payload_size;
    
    pack.tcp_payload_size = 1;
    tcp.update(&pack);
    test.node(3).has_seq(7).has_length(1);
    tcph.th_seq += pack.tcp_payload_size;

    tcp.update(&pack);
    test.node(4).has_seq(8).has_length(1);
    tcph.th_seq += pack.tcp_payload_size;

    pack.tcp_payload_size = 0;
    tcp.update(&pack);
    test.node(5).has_seq(tcph.th_seq).has_length(0);

    assert(!tcp.stats.gaps && !tcp.stats.overlaps && !tcp.stats.retrans);
}

void tcp_reverse() {
    TCP_TEST_SETUP

// TODO: SYN at end

    tcph.th_seq = 10 ;
    pack.tcp_payload_size = 1;
    tcp.update(&pack);
    test.node(1).has_seq(10).has_length(1);

    tcph.th_seq = 7;
    pack.tcp_payload_size = 0;
    tcp.update(&pack);
    test.node(1).has_seq(7).has_length(0);

    pack.tcp_payload_size = 3;
    tcp.update(&pack);
    test.node(2).has_seq(7).has_length(3);
    
    pack.tcp_payload_size = 5;
    tcph.th_seq = 2;
    tcp.update(&pack);
    test.node(1).has_seq(2).has_length(5);

    assert(tcp.stats.gaps == 2); // Double check this
    assert(tcp.stats.overlaps == 0);
    assert(tcp.stats.retrans == 0);
}

void tcp_semi_rand() {
    TCP_TEST_SETUP

    pack.tcp_payload_size = 5;

    tcph.th_seq = 12;
    tcp.update(&pack);

    tcph.th_seq = 2;
    tcp.update(&pack);

    tcph.th_seq = 17;
    tcp.update(&pack);

    tcph.th_seq = 7;
    tcp.update(&pack);

    // confirm in-order
    // 4 segments. Each with 5 byte payloads
    auto it=tcp.segs.begin();
    assert(it->seq == 1);
    it++;
    for(int i=2; i < 4*5; i += 5) {
        assert(it != tcp.segs.end());
        assert(it->seq == i);
        assert(it->len == 5);
        it++;
    }

    assert(tcp.stats.gaps == 1); // XXX don't think so... revisit
    assert(tcp.stats.overlaps == 0);
    assert(tcp.stats.retrans == 0);
}

void swap(int *src, int i, int j) {
    int tmp=src[i];
    src[i] = src[j];
    src[j] = tmp;
}

void tcp_fuzz() {
    TCP_TEST_SETUP

    int its = 100;
    int input[its];

    for(int i=0; i<its; i++) {
        input[i] = i+1;
    }

    for(int i=0; i<its; i++) {
        swap(input, rand() % its, rand() % its);
    }

    pack.tcp_payload_size = 1;

    for(int i=0; i<its; i++) {
        // Random seq
        tcph.th_seq = input[i];
        tcp.update(&pack);
    }

    // print_segs(tcp);

    for(int i=1; i<its; i++) {
        // Make sure inorder
        test.node(i).has_seq(i);
    }

    assert(!tcp.stats.overlaps && !tcp.stats.retrans);
}

void tcp_overlap() {
    TCP_TEST_SETUP

    pack.tcp_payload_size = 5;
    tcp.update(&pack);
    tcph.th_seq += pack.tcp_payload_size;

    tcp.update(&pack);

    test.node(1).has_seq(2).has_length(5);
    test.node(2).has_seq(7).has_length(5);
    
    // New packet, overlapping them...
    tcph.th_seq = 4;
    tcp.update(&pack);

    // XXX Current handling is to just put it in between
    test.node(1).has_seq(2).has_length(5);
    test.node(2).has_seq(4).has_length(5);
    test.node(3).has_seq(7).has_length(5);

    assert(tcp.stats.overlaps == 1);
}

void tcp_retrans() {
    TCP_TEST_SETUP

    pack.tcp_payload_size = 5;
    tcp.update(&pack);
    tcp.update(&pack);
    assert(tcp.stats.retrans == 1);

    pack.tcp_payload_size = 0;

    tcp.update(&pack);
    // Not a retrans since the payload size differs
    assert(tcp.stats.retrans == 1);
    
    // Not a retrans since ack differs
    tcph.th_ack++;
    tcp.update(&pack);
    assert(tcp.stats.retrans == 1);

    tcp.update(&pack);
    assert(tcp.stats.retrans == 2);
}

void tcp_assem() {
    tcp_basic();
    tcp_forward();
    tcp_reverse();
    tcp_semi_rand();
    tcp_overlap();
    tcp_retrans();
    tcp_delayed_syn();
}

int main() {
    tcp_assem();
    return 0;
}
