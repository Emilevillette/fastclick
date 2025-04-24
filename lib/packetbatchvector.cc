// -*- related-file-name: "../include/click/packetbatchvector.hh" -*-
/*
 * packetbatchvector.{cc,hh} -- a batch of packet, using a vector
 * Tom Barbette
 *
 * Copyright (c) 2015-2016 University of Liege
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, subject to the conditions
 * listed in the Click LICENSE file. These conditions include: you must
 * preserve this copyright notice, and you cannot mention the copyright
 * holders in advertising related to the Software without their permission.
 * The Software is provided WITHOUT ANY WARRANTY, EXPRESS OR IMPLIED. This
 * notice is a summary of the Click LICENSE file; the license in that file is
 * legally binding.
 */

#include <click/config.h>
#include <click/packetbatchvector.hh>
#include <click/netmapdevice.hh>
# include <click/dpdkdevice.hh>

CLICK_DECLS

MemoryPool<PacketBatchVector> PacketBatchVector::batch_pool;

#if HAVE_BATCH

#if CLICK_PACKET_USE_DPDK
rte_mempool *PacketBatchVector::get_mempool_forward() {
    return DPDKDevice::get_mpool(0);
}
#endif

#if HAVE_CLICK_PACKET_POOL


/**
 * Recycle a whole batch, faster in most cases as it add batches to the pool in
 * two calls.
 *
 * If you are iterating over all packets, consider doing the same than this
 *  function directly to avoid dual iteration.
 */
void PacketBatchVector::fast_kill() {
    BATCH_RECYCLE_START_VEC();
    FOR_EACH_PACKET_SAFE_VEC(this,up) {
        WritablePacket* p = static_cast<WritablePacket*>(up);
        BATCH_RECYCLE_PACKET_VEC(p);
        pop_at(i);
    }
    batch_pool.releaseMemory(this);
    BATCH_RECYCLE_END_VEC();
}

/**
 * Recycle a whole batch, faster in most cases than a loop of kill_nonatomic
 */
void PacketBatchVector::fast_kill_nonatomic() {
    BATCH_RECYCLE_START_VEC();
    FOR_EACH_PACKET_SAFE_VEC(this,up) {
        WritablePacket* p = static_cast<WritablePacket*>(up);
        BATCH_RECYCLE_PACKET_NONATOMIC_VEC(p);
        pop_at(i);
    }
    batch_pool.releaseMemory(this);
    BATCH_RECYCLE_END_VEC();
}
# endif

/** @brief Create and return a batch of packets made from a contiguous buffer
 * @param count number of packets
 *
 * @param data data used in the new packet
 * @param length array of packets length
 * @param destructor destructor function
 * @param argument argument to destructor function
 * @return new packet batch, or null if no packet could be created
 *
 **/
PacketBatchVector *
PacketBatchVector::make_batch(unsigned char *data, uint16_t count, uint16_t *length,
        Packet::buffer_destructor_type destructor, void* argument, bool clean)
{
#if CLICK_PACKET_USE_DPDK
    click_chatter("UNIMPLEMENTED");
    assert(false); //TODO
#else

# if HAVE_CLICK_PACKET_POOL
    WritablePacket *p = WritablePacket::pool_batch_allocate(count);
# else
    WritablePacket *p = new WritablePacket;
# endif
    WritablePacket *head = p;
    WritablePacket *last = p;
    uint16_t i = 0;
    while(p) {
        p->initialize(clean);
        p->_head = p->_data = data;
        p->_tail = p->_end = data + length[i];
        data += length[i] & 63 ? (length[i] & ~63) + 64 : length[i];
        ++i;
        p->_destructor = destructor;
        p->_destructor_argument = argument;
        last = p;
#if HAVE_CLICK_PACKET_POOL
        p = static_cast<WritablePacket *>(p->next());
#else
        p = new WritablePacket;
#endif
    }
    if (i != count) {
        click_chatter("Size of list %d, expected %d\n", i, count);
    }
#if HAVE_FLOW
    if (fcb_stack)
        fcb_stack->acquire(count);
#endif
    return PacketBatchVector::make_from_simple_list(head, last, i);
#endif
}

#endif //HAVE_BATCH

CLICK_ENDDECLS
