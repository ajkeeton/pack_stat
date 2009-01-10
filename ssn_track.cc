
#include <stdio.h>
#include "ssn_track.h"

ssn_stats_t ssn_stats;

ssn_tbl_t *ssn_tbl_alloc()
{
    return new ssn_tbl_t;
}

void ssn_tbl_save(
    ssn_tbl_t *table, ssn_tbl_key_t *key, void *data, 
    uint32_t len, void (*free_cb)(void *))
{
    ssn_node_t ssn;
    ssn.data = data;
    ssn.len = len;
    ssn.ssn_node_cleanup = free_cb;
    table->insert(std::pair<ssn_tbl_key_t, ssn_node_t>(*key, ssn));
    ssn_stats.hash_inserts++;
}

void *ssn_tbl_find(ssn_tbl_t *table, ssn_tbl_key_t *key)
{
    ssn_tbl_t::iterator it = table->find(*key);
    
    if(it == table->end()) {
        ssn_stats.hash_misses++;
        return NULL;
    }

    return it->second.data;
}

void ssn_tbl_clear(ssn_tbl_t *table, ssn_tbl_key_t *key)
{
    ssn_tbl_t::iterator it = table->find(*key);

    if(it == table->end())
        return;

    table->erase(it);
}

void ssn_tbl_dump()
{
    printf("\tInserts:              %ld\n", ssn_stats.hash_inserts);
    printf("\tClears:               %ld\n", ssn_stats.hash_clears);
    printf("\tCollisions:           %ld\n", ssn_stats.hash_collisions);
    printf("\tMisses:               %ld\n", ssn_stats.hash_misses);
}
