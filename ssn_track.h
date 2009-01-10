#pragma once

#include <stdint.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <map>
#include <netinet/in.h>

using namespace std;

struct ssn_stats_t {
    uint64_t hash_inserts,
             hash_clears,
             hash_collisions,
             hash_misses,
             timeouts,
             timeout_nodes;
};

static inline int CMP8(const uint64_t x, const uint64_t y)
{
    if(x < y) return -1;
    if(x > y) return 1;
    return 0;
}

static inline int CMP16(const uint64_t x[2], const uint64_t y[2])
{
    if(x[0] != y[0]) return CMP8(x[0], y[0]);
    return CMP8(x[1], y[1]);
}

static inline int CMP16(const uint32_t x[4], const uint32_t y[4])
{
    return CMP16((uint64_t*)x, (uint64_t*)y);
}

extern ssn_stats_t ssn_stats;

class ssn_tbl_key_t {
public:
    uint32_t client_ip[4],
             server_ip[4];
    uint16_t client_port,
             server_port,
             vlan_tag;
    ssn_tbl_key_t() 
    { 
        client_ip[0] = client_ip[1] = client_ip[2] = client_ip[3] =
        server_ip[0] = server_ip[1] = server_ip[2] = server_ip[3] = 0;
        client_port = server_port = vlan_tag = 0;
    }
    ssn_tbl_key_t(const ssn_tbl_key_t &t)
    {
        client_ip[0] = t.client_ip[0];
        client_ip[1] = t.client_ip[1];
        client_ip[2] = t.client_ip[2];
        client_ip[3] = t.client_ip[3];

        server_ip[0] = t.server_ip[0];
        server_ip[1] = t.server_ip[1];
        server_ip[2] = t.server_ip[2];
        server_ip[3] = t.server_ip[3];

        client_port = t.client_port;
        server_port = t.server_port;

        vlan_tag = t.vlan_tag;
    }

    ssn_tbl_key_t(int family, uint32_t *src_ip, uint32_t *dst_ip,
                       uint16_t dst_port, uint16_t src_port, uint16_t vlan){
        if(src_port > dst_port) {
            client_ip[0] = src_ip[0];
            server_ip[0] = dst_ip[0];

            if(family != AF_INET) {
                client_ip[1] = src_ip[1];
                server_ip[1] = dst_ip[1];
                client_ip[2] = src_ip[2];
                client_ip[3] = src_ip[3];
                server_ip[2] = dst_ip[2];
                server_ip[3] = dst_ip[3];
            }
            else {
                client_ip[1] = 0;
                server_ip[1] = 0;
                client_ip[2] = 0;
                client_ip[3] = 0;
                server_ip[2] = 0;
                server_ip[3] = 0;
            }

            client_port = src_port;
            server_port = dst_port;
        }
        else {
            server_ip[0] = src_ip[0];
            client_ip[0] = dst_ip[0];

            if(family != AF_INET) {
                server_ip[1] = src_ip[1];
                client_ip[1] = dst_ip[1];
                server_ip[2] = src_ip[2];
                server_ip[3] = src_ip[3];
                client_ip[2] = dst_ip[2];
                client_ip[3] = dst_ip[3];
            }
            else {
                server_ip[1] = 0;
                client_ip[1] = 0;
                server_ip[2] = 0;
                server_ip[3] = 0;
                client_ip[2] = 0;
                client_ip[3] = 0;
            }

            server_port = src_port;
            client_port = dst_port;
        }

        vlan_tag = vlan;
    }

    bool operator<(const ssn_tbl_key_t &k) const 
    {
        /* Order of comparisons chosen intentionally */
        if(client_port != k.client_port)
            return client_port < k.client_port;

        int c = CMP16(client_ip, k.client_ip);

        if(c)
            return c < 0;

        c = CMP16(server_ip, k.server_ip);

        if(c)
            return c < 0;

        if(server_port != k.server_port)
            return server_port < k.server_port;

        if(vlan_tag != k.vlan_tag)
            return vlan_tag < k.vlan_tag;

        return 0;
    }

    bool operator==(const ssn_tbl_key_t &rh) const
    {
        if(this == &rh) return true;
        return 
                // Order is intentional
                client_port == rh.client_port && 

                client_ip[3] == rh.client_ip[3] &&
                client_ip[2] == rh.client_ip[2] && 
                client_ip[1] == rh.client_ip[1] && 
                client_ip[0] == rh.client_ip[0] && 

                server_ip[3] == rh.server_ip[3] &&
                server_ip[2] == rh.server_ip[2] &&
                server_ip[1] == rh.server_ip[1] &&
                server_ip[0] == rh.server_ip[0] &&
                server_port == rh.server_port &&

                vlan_tag == rh.vlan_tag;
    }

    bool operator!=(const ssn_tbl_key_t &rh) const
    {
        return !(*this == rh);
    }

    ssn_tbl_key_t &operator=(const ssn_tbl_key_t &rh)
    {
        client_ip[0] = rh.client_ip[0];
        client_ip[1] = rh.client_ip[1];
        client_ip[2] = rh.client_ip[2];
        client_ip[3] = rh.client_ip[3];

        server_ip[0] = rh.server_ip[0];
        server_ip[1] = rh.server_ip[1];
        server_ip[2] = rh.server_ip[2];
        server_ip[3] = rh.server_ip[3];

        client_port = rh.client_port;
        server_port = rh.server_port;
        vlan_tag = rh.vlan_tag;

        return *this;
    }
};

class ssn_node_t {
public:
    ssn_node_t() : data(NULL), len(0), ssn_node_cleanup(NULL) {}

    ~ssn_node_t() { 
        if(data && ssn_node_cleanup) {
            ssn_node_cleanup(data); 
            ssn_stats.hash_clears++;
        }
    }

    ssn_node_t &operator=(const ssn_node_t &s) {
        data = s.data;
        len = s.len;
        ssn_node_cleanup = s.ssn_node_cleanup;
        const_cast<ssn_node_t &>(s).data = NULL;
        const_cast<ssn_node_t &>(s).len = 0;
        return *this;
    }

    ssn_node_t(const ssn_node_t &s) {
        *this = s;
    }

    void *data;
    uint32_t len;
    void (*ssn_node_cleanup)(void *);
};

typedef std::map<ssn_tbl_key_t, ssn_node_t> ssn_tbl_t; 

void ssn_tbl_save(
    ssn_tbl_t *table, ssn_tbl_key_t *key, void *data,
    uint32_t len, void (*free_cb)(void *));
void *ssn_tbl_find(ssn_tbl_t *table, ssn_tbl_key_t *key);
void ssn_tbl_clear(ssn_tbl_t *table, ssn_tbl_key_t *key);
void ssn_tbl_timeout_node(ssn_node_t *row);
void ssn_tbl_free(ssn_tbl_t *tbl);
ssn_tbl_t *ssn_tbl_alloc();
void ssn_tbl_dump();
void SSN_FREE(void *);
char *key_to_string(ssn_tbl_key_t key);
