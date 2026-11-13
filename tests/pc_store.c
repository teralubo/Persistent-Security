#include "pc_store.h"

#include <string.h>

static PsStoreResult ps_pc_read(void* context, uint8_t* out, size_t size) {
    PsPcStore* store = context;
    if(store->fail_next_read) {
        store->fail_next_read = false;
        return PsStoreError;
    }
    if(!store->exists) return PsStoreNotFound;
    if(size != sizeof(store->record)) return PsStoreError;
    memcpy(out, store->record, sizeof(store->record));
    return PsStoreOk;
}

static bool ps_pc_write_atomic(void* context, const uint8_t* data, size_t size) {
    PsPcStore* store = context;
    if(store->fail_next_write) {
        store->fail_next_write = false;
        return false;
    }
    if(size != sizeof(store->record)) return false;
    memcpy(store->record, data, sizeof(store->record));
    store->exists = true;
    ++store->write_count;
    return true;
}

static bool ps_pc_random(void* context, uint8_t* out, size_t size) {
    PsPcStore* store = context;
    for(size_t i = 0; i < size; ++i) {
        store->random_counter = (uint8_t)(store->random_counter + 37U);
        out[i] = store->random_counter;
    }
    return true;
}

void ps_pc_store_init(PsPcStore* store) {
    memset(store, 0, sizeof(*store));
}

PsStore ps_pc_store_interface(PsPcStore* store) {
    return (PsStore){
        .context = store,
        .read_record = ps_pc_read,
        .write_record_atomic = ps_pc_write_atomic,
    };
}

PsRandom ps_pc_random_interface(PsPcStore* store) {
    return (PsRandom){.context = store, .fill = ps_pc_random};
}
