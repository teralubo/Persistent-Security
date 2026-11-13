#ifndef PS_PC_STORE_H
#define PS_PC_STORE_H

#include "ps_security.h"

typedef struct {
    uint8_t record[PS_RECORD_SIZE];
    bool exists;
    bool fail_next_read;
    bool fail_next_write;
    uint8_t random_counter;
    unsigned write_count;
} PsPcStore;

void ps_pc_store_init(PsPcStore* store);
PsStore ps_pc_store_interface(PsPcStore* store);
PsRandom ps_pc_random_interface(PsPcStore* store);

#endif
