// -*- related-file-name: "../../lib/packetbatchvector.cc" -*-
#ifndef CLICK_PACKETBATCHVECTOR_HH
#define CLICK_PACKETBATCHVECTOR_HH


#include <click/vector.hh>
#include <click/packet.hh>
#include <click/memorypool.hh>
CLICK_DECLS

#define BATCH_POOL_INITIAL_SIZE 512

//TODO: CLEANUP

/**
 * Iterate over all packets of a batch. The batch cannot be modified during
 *   iteration. Use _SAFE version if you want to modify it on the fly.
 */

#define FOR_EACH_PACKET_VEC(batch,p) Packet *p = batch->first(); for(unsigned int i=0; i < batch->count(); i++, p=((PacketBatchVector *) batch)->at(i))

/**
 * Iterate over all packets of a batch. The batch cannot be modified during
 *   iteration. Use _SAFE version if you want to modify it on the fly.
 */
//OBSOLETE, REWRITE FOR VECTOR
//#define FOR_EACH_PACKET(batch,p) FOR_EACH_PACKET_VEC(batch->first(),p)

/**
 * Iterate over all packets of a batch. The current packet can be modified
 *  during iteration as the "next" pointer is read before going in the core of
 *  the loop.
 */
#define FOR_EACH_PACKET_SAFE_VEC(batch,p) \
                Packet* fep_next = batch->count() > 0 ? ((PacketBatchVector *) batch)->at(1) : 0;\
                Packet* p = batch->first();\
                for(unsigned int i=0; i < batch->count(); i++, p=fep_next, fep_next=(p==0?0:((PacketBatchVector *) batch)->at(i+1)))

// Alias for the old name
#define FOR_EACH_PACKET_VEC_SAFE FOR_EACH_PACKET_SAFE_VEC

//#define FOR_EACH_PACKET_SAFE(batch,p) FOR_EACH_PACKET_VEC_SAFE(batch->first(),p)

/**
 * Execute a function on each packets of a batch. The function may return
 * another packet to replace the current one. This version cannot drop !
 * Use _DROPPABLE version if the function could return null.
 */
#define EXECUTE_FOR_EACH_PACKET_VEC(fnt,batch) \
                Packet *p = nullptr;\
                for(unsigned int i=0; i<batch->count();i++, p=((PacketBatchVector*) batch)->at(i)){\
                    Packet *q = fnt(p);\
                    if(p != q) {\
                        batch->set_at(i, q);\
                    }\
                }

/**
 * Execute a function that returns a bool on each packets of a batch.
 * The function may take the packet by reference and change the reference.
 * If the function returns false, the loop stops and on_stop is called
 * with the whole batch in argument, the packet causing the stop, and the next
 * reference. This function does not kill any packet by itself.
 */
//OBSOLETE, REWRITE FOR VECTOR
#define EXECUTE_FOR_EACH_PACKET_UNTIL_DO_VEC(fnt,batch,on_stop) \
                Packet* p = batch->first();\
                for(unsigned int i=0; i < batch->count(); i++, p=((PacketBatchVector*) batch)->at(i)){\
                    Packet* q = p;\
                    bool drop = !fnt(q);\
                    if (q != p) {\
                        batch->set_at(i, q);\
                    }\
                    if(unlikely(drop)) {\
                        on_stop(batch, q, i+1 < batch->count() ? ((PacketBatchVector*) batch)->at(i+1) : 0);\
                        break;\
                    }\
                }

//Variant that will drop the whole batch when fnt return false
#define EXECUTE_FOR_EACH_PACKET_UNTIL_VEC(fnt,batch) \
    EXECUTE_FOR_EACH_PACKET_UNTIL_DO_VEC(fnt, batch, [](PacketBatchVector*& batch, Packet*, Packet*){batch->kill();batch = 0;})

/*
 * Variant that will drop the remaining packets, but return the batch up to the drop (the packet for which fnt returned true is included).
 * A usage example is a NAT, that translate all packets up to when the state is destroyed. But sometimes there could be unordered packets still coming after the last ACK, or duplicate FIN.
 */
#define EXECUTE_FOR_EACH_PACKET_UNTIL_DROP_VEC(fnt,batch) \
                Packet* p = batch->first();\
                for(unsigned int i=0; i < batch->count(); i++, p=((PacketBatchVector*) batch)->at(i)){\
                    Packet* q = p;\
                    bool drop = !fnt(q);\
                    if (q != p) {\
                        batch->set_at(i, q);\
                    }\
                    if(unlikely(drop)) {\
                        if(i != batch->count()-1) {\
                            PacketBatchVector* remaining = batch->split(i+1);\
                            remaining->kill();\
                            break;\
                        }\
                    }\
                }

/**
 * Execute a function on each packet of a batch.
 * The batch will be modified in-place according to the output of the function.
 *
 * The function may return
 * another packet and which case the packet of the batch will be replaced by
 * that one, or null if the packet is to be dropped.
 *
 * If all packets are dropped, batch will become null. If the first packets are dropped, the address of batch will change.
 *
 *
 * Example: EXECUTE_FOR_EACH_PACKET_DROPPABLE([this](Packet* p){return p->push(_nbytes);},batch,[](Packet* p){})
 */
#define EXECUTE_FOR_EACH_PACKET_DROPPABLE_VEC(fnt,batch,on_drop) {\
                Packet* p = batch->first();\
                int count = batch->count();\
                int revised_count = batch->count();\
                int current_pos = 0;\
                for(int i = 0; i < count; i++, p=batch->at(i)){\
                    Packet* q = fnt(p);\
                    if (q == 0) {\
                        on_drop(p);\
                        revised_count--;\
                    } else if (q != p) {\
                        batch->set_at(current_pos, q);\
                        current_pos++;\
                    }\
                }\
                for(int i = revised_count; i < count; i++) {\
                    batch->pop_at(i);\
                }\
            }

/**
 * Same as EXECUTE_FOR_EACH_PACKET_DROPPABLE but build a list of dropped packet
 * instead of calling a function
 */
#define EXECUTE_FOR_EACH_PACKET_DROP_LIST_VEC(fnt,batch,drop_list) \
        PacketBatchVector* drop_list = 0;\
        auto on_drop = [&drop_list](Packet* p) {\
            if (drop_list == 0) {\
                drop_list = PacketBatchVector::make_from_packet(p);\
            } else {\
                drop_list->append_packet(p);\
            }\
        };\
        EXECUTE_FOR_EACH_PACKET_DROPPABLE_VEC(fnt,batch,on_drop);


/**
 * Execute a function on each packet of a batch. The function may return
 * the same packet if nothing is to change,
 * another packet in which case it will repair the batch,
 * or null. If it returns null, the batch
 * is flushed using on_flush and processing continue on a new batch starting
 * at the next packet. on_drop is called on the packet that was returned
 * as null after flushing.
 * On_flush is always called on the batch after the last packet.
 */
 //NOT IMPLEMENTED
#define EXECUTE_FOR_EACH_PACKET_SPLITTABLE_VEC(fnt,batch,on_drop,on_flush) {}


/**
 * Execute a function for each packet, passing parameters to easily add multiple packets to the list
 *
 * An example that does nothing in practice :
 * void fnt(Packet *p, std::function<void(Packet*)>push) {
 *    push(p);
 * }
 * EXECUTE_FOR_EACH_PACKET_ADD( fnt, batch );
 */
#define EXECUTE_FOR_EACH_PACKET_ADD_VEC(fnt,batch) {\
            Packet* p = batch->first();\
            Packet* last = 0;\
            int count = 0;\
            for(int i = 0; i < count; i++, p=batch->at(i)){\
                auto add = [&batch,&last,&count, i](Packet*q) {\
                    batch->set_at(i, q);\
                    last = q;\
                    count++;\
                };\
                fnt(p,add);\
            }\
            if (!likely(last)) {\
	            batch = 0;\
	        }\
        }\

/**
 * Split a batch into multiple batch according to a given function which will
 * give the index of an output to choose.
 *
 * The main use case is the classification element like Classifier, Switch, etc
 *   where you split a batch checking which output each packets should take.
 *
 * @args nbatches Number of output batches. In many case you want noutputs() + 1
 *      , keeping the last one for drops.
 * @args fnt Function to call which will return a value between 0 and nbatches.
 *  If the function returns a values < 0 or bigger than nbatches, the last batch
 *  of nbatches will be used.
 * @args cep_batch The batch to be split
 * @args on_finish function which take an output index and the batch when
 *  classification is finished, usually you want that to be
 *  checked_output_push_batch.
 */
#define CLASSIFY_EACH_PACKET_VEC(nbatches,fnt,cep_batch,on_finish)\
    {\
        PacketBatchVector* out[(nbatches)];\
        bzero(out,sizeof(PacketBatchVector*)*(nbatches));\
        Packet* p = cep_batch->first();\
        \
        for (unsigned int i=0; i<cep_batch->count(); i++, p=((PacketBatchVector*) cep_batch)->at(i)) {\
            int o = fnt(p);\
            if (o < 0 || o>=(int)(nbatches)) o = (nbatches - 1);\
            if(!out[o]) {\
                out[o] = PacketBatchVector::make_from_packet(p);\
            } else {\
                out[o]->append_packet(p);\
            }\
        }\
\
        for (unsigned i = 0; i < (unsigned)(nbatches); i++) {\
            if (out[i]) {\
                (on_finish(i,out[i]));\
            }\
        }\
    }

/**
 * Equivalent to CLASSIFY_EACH_PACKET but ignore the packet if fnt returns -1
 */
//! initialize properly packetbatches ?
//! what to do with reinterpret_cast
#define CLASSIFY_EACH_PACKET_IGNORE_VEC(nbatches,fnt,cep_batch,on_finish)\
    {\
        PacketBatchVector* out[(nbatches)];\
        bzero(out,sizeof(PacketBatchVector*)*(nbatches));\
        Packet* p = cep_batch->first();\
        \
        for (unsigned int i=0; i<cep_batch->count(); i++, p=((PacketBatchVector*) cep_batch)->at(i)) {\
            int o = fnt(p);\
            if (o < 0 || o>=(int)(nbatches)) o = (nbatches - 1);\
            if(o != -1) {\
                if(!out[o]) {\
                    out[o] = PacketBatchVector::make_from_packet(p);\
                } else {\
                    out[o]->append_packet(p);\
                }\
            }\
        }\
\
        for (unsigned i = 0; i < (unsigned)(nbatches); i++) {\
            if (out[i]) {\
                (on_finish(i,out[i]));\
            }\
        }\
    }


/**
 * Create a batch by calling multiple times (up to max) a given function and
 *   linking them together in respect to the PacketBatchVector semantic.
 *
 * In most case this function should not be used. Because if you get packets
 * per packets it means you don't get them upstream as a batch. You may prefer
 * to somehow fetch a whole batch and then iterate through it. One bad
 * use case is MAKE_BATCH(pull ...) in a x/x element which will create a batch
 * by calling multiple times pull() until it returns no packets.
 * This will break batching as it will call pull on the previous element
 * instead of pull_batch. However this is fine in a source element where
 * anyway the batch must be created packet per packet.
 */
#define MAKE_BATCH_VEC(fnt,head,max) {\
        head = PacketBatchVector::make_from_packet(fnt);\
        if (head != 0) {\
            unsigned int count = 1;\
            while (count < (unsigned)(max>0?max:BATCH_MAX_PULL)) {\
                Packet* current = fnt;\
                if (current == 0)\
                    break;\
                head->append_packet(current);\
                count++;\
            }\
        }\
    }
/**
 * Batch of Packet.
 * This class has no field member and can be cast to or from Packet. It is
 *  only there as a way to remember what we are handling and provide useful
 *  functions for managing packets as a batch.
 *
 * Internally, the head contains all the information usefull for the batch. The
 *  prev annotation points to the tail, the next to the next packet. It is
 *  implemented by a *simply* linked list. The BATCH_COUNT annotation is set
 *  on the first packet of the batch to remember the number of packets in the
 *  batch.
 *
 * Batches must not mix cloned and unique packets. Use cut to split batches and have part of them cloned.
 */
class PacketBatchVector {

//Consider a batch size bigger as bogus (prevent infinite loop on bad pointer manipulation)
#define MAX_BATCH_SIZE 8192

private:
    Packet* packets[MAX_BATCH_SIZE] = {nullptr};
    int batch_size = 0;
    static per_thread<MemoryPool<PacketBatchVector>> batch_pool;

public :

    /**
     * Return the first packet of the batch
     */
    inline Packet* first() {
        return count() == 0 ? nullptr : packets[0];
    }

    /**
     * Set the tail of the batch
     */
    inline void set_tail(Packet* p) {
        //not needed
        (void)p;
    }

    /**
     * Return the tail of the batch
     */
    inline Packet* tail() {
        return count() == 0 ? nullptr : packets[count() - 1];
    }

    /**
     * Return the packet at position pos
     *
     * @param pos The position of the packet in the batch
     * @return The packet at position pos
     */
    inline Packet* at(unsigned int pos) {
        if (pos >= MAX_BATCH_SIZE) {
            click_chatter("Error: PacketBatchVector::at: pos %u is bigger than MAX_BATCH_SIZE %u", pos, MAX_BATCH_SIZE);
            return nullptr;
        }
		return packets[pos];
    }

    inline void at_range_offset(int32_t offsets[16], unsigned int pos, unsigned int count) {
        click_chatter("at range");
        for(unsigned int i = 0; i < count; i++) {
            offsets[i] = (char *)at(pos + i) - (char *)0;
        }
    }

    /**
     * set the packet p at position pos
     *
     * @param pos The position of the packet in the batch
     * @param p The packet to set at position pos
     */
    inline void set_at(unsigned int pos, Packet* p) {
        if (pos >= MAX_BATCH_SIZE) {
            click_chatter("Error: PacketBatchVector::set_at: pos %u is bigger than MAX_BATCH_SIZE %u", pos, MAX_BATCH_SIZE);
            return;
        }
        if(pos >= count()) {
            click_chatter("Error: PacketBatchVector::set_at: pos %u is bigger than size of batch %u", pos, count());
            return;
        }
        packets[pos] = p;
    }

    /**
     * @brief Allocate a new PacketBatchVector from a memory pool
     *
     * @return a pointer to a PacketBatchVector allocated with a MemoryPool
     */
    inline static PacketBatchVector * make_packet_batch_from_pool() {
        PacketBatchVector* b = batch_pool->getMemory();
        click_chatter("GET MEMORY, current alloc: %u, max alloc: %u, alloc count: %u, current cpu: %u", batch_pool->current_alloc, batch_pool->max_alloc, batch_pool->alloc_count, click_current_cpu_id());
        return b;
    }

    /*
     * Append a simply-linked list of packet to the batch.
     * One must therefore pass the tail and the number of packets to do it in constant time. Chances are you
     * just created that list and can track that.
     */
    // DEPRECATED
    inline void append_simple_list(Packet* lhead, Packet* ltail, int lcount) {
        //Unsuported
        (void)lhead;
        (void)ltail;
        (void)lcount;
    }

    /**
     * Append a proper PacketBatchVector to this batch.
     */
    inline void append_batch(PacketBatchVector* head) {
        for(unsigned int i = 0; i < head->count(); i++) {
            append_packet(head->at(i));
        }
    }

    /**
     * Append a packet to the list.
     */
    inline void append_packet(Packet* p) {
        if(count() >= MAX_BATCH_SIZE) {
            click_chatter("Error: PacketBatchVector::append_packet: batch is full, cannot append packet");
            return;
        }
        packets[count()] = p;
        batch_size++;
    }

    /**
     * Return the number of packets in this batch
     */
    inline unsigned count() {
        return batch_size;
    }

    /**
     * @brief Start a new batch
     *
     * @param p A packet
     *
     * Creates a new batch, with @a p as the first packet. Batch is *NOT* valid
     *  until you call make_tail().
     * If the Packet is null, returns no batch.
     */
    inline static PacketBatchVector* start_head(Packet* p) {
        return make_from_packet(p);
    }

    /**
     * @brief Finish a batch started with start_head()
     *
     * @param last The last packet of the batch
     * @param count The number of packets in the batch
     *
     * @return The whole packet batch
     *
     * This will set up the batch with the last packet. set_next() have to be called for each packet from the head to the @a last packet !
     */
    inline PacketBatchVector* make_tail(Packet* last, unsigned int count) {
        (void)last;
        (void)count;
        return this;
    }

    /**
     * Set the number of packets in this batch
     */
    //DEPRECATED
    inline void set_count(unsigned int c) {
        (void)c;
    }

    /**
     * @brief Cut a batch in two batches
     *
     * @param middle The last packet of the first batch
     * @param first_batch_count The number of packets in the first batch
     * @param second Reference to set the head of the second batch
     */
    inline void cut(Packet* middle, int first_batch_count, PacketBatchVector* &second) {
        if (middle == 0) {
            second = 0;
            click_chatter("BUG Warning : cutting a batch without a location to cut !");
            return;
        }

        if (middle == tail()) {
            second = 0;
            return;
        }

        second = make_from_packet(packets[first_batch_count]);
        for(unsigned int i = first_batch_count + 1; i < count(); i++) {
            second->append_packet(packets[i]);
            pop_at(i);
        }
    }

    /**
     * @brief Cut a batch in two batches
     *
     * @param first_batch_count The number of packets in the first batch
     * @param second Reference to set the head of the second batch
     * @param safe Set to true for optimization if you're sure there is enough packets to cut, and first_batch_count is not 0
     */
    inline void split(int first_batch_count, PacketBatchVector* &second, const bool &safe = false) {
        Packet* middle = first();
        if (unlikely(!safe)) {
            assert(first_batch_count > 0);
        }
        for (int i = 0; i < first_batch_count - 1; i++) {
            middle = packets[i + 1];
            if (unlikely(!safe && middle == 0)) {
                second = 0;
                break;
            }
        }

        second = make_from_packet(packets[first_batch_count]);
        for(unsigned int i = first_batch_count + 1; i < count(); i++) {
            second->append_packet(packets[i]);
            pop_at(i);
        }
    }

    inline PacketBatchVector* split(int first_batch_count) {
        PacketBatchVector* second;
        split(first_batch_count,second, false);
        return second;
    }

    /**
     * Remove the first packet
     * @return the new batch without front. Do not use "this" afterwards!
     */
    PacketBatchVector* pop_front() {
        if (count() == 1)
            return 0;

        PacketBatchVector* b = make_packet_batch_from_pool();
        for(unsigned int i = 1; i < count(); i++) {
            b->append_packet(packets[i]);
        }
        soft_kill();
        return b;
    }

    /**
     * Remove the packet at the given position. This does NOT shift the remaning packets to the left, use with caution.
     *
     * @param pos The position of the packet to remove
     */
    inline void pop_at(unsigned int pos) {
        if(pos >= count()) {
            click_chatter("Error: PacketBatchVector::pop_at_safe: pos %u is bigger than size of batch %u", pos, count());
            return;
        }
        packets[pos] = nullptr;
        batch_size--;
    }

    /**
     * Remove the packet at the given position. This shifts the remaning packets to the left.
     *
	 * Warning: this is an expensive operation, use with caution.
     * @param pos The position of the packet to remove
     */
    inline void pop_at_safe(unsigned int pos) {
        if(pos >= count()) {
            click_chatter("Error: PacketBatchVector::pop_at_safe: pos %u is bigger than size of batch %u", pos, count());
            return;
        }
        batch_size--;
        // Shift the remaining packets to the left
        for(unsigned int i = pos; i < count(); i++) {
            packets[i] = packets[i+1];
        }
        // pop the last packet
        packets[count()] = nullptr;
    }

    /**
     * Build a batch from a linked list of packet for which head->prev is the tail and tail->next is already 0
     *
     * @param head The first packet of the batch
     * @param size Number of packets in the linkedlist
     *
     * @pre The "prev" annotation of the first packet must point to the last packet of the linked list
     * @pre The tail->next() packet must be zero
     */
    inline static PacketBatchVector* make_from_tailed_list(Packet* head, unsigned int size) {
        PacketBatchVector* b = make_packet_batch_from_pool();
        Packet* current = head;
        for (unsigned int i = 1; i < size; i++) {
            b->append_packet(current);
            current = current->next();
        }
        return b;
    }

    /**
     * Build a batch from a linked list of packet
     *
     * @param head The first packet of the batch
     * @param tail The last packet of the batch
     * @param size Number of packets in the linkedlist
     */
    inline static PacketBatchVector* make_from_simple_list(Packet* head, Packet* tail, unsigned int size) {
        (void) tail;
        return make_from_tailed_list(head,size);
    }

    /**
     * Build a batch from a linked list of packet ending by a next==0 pointer. O(n).
     *
     * @param head The first packet of the batch
     */
    inline static PacketBatchVector* make_from_simple_list(Packet* head) {
        int size = 1;
        Packet* next = head->next();
        Packet* tail = head;
        while (next != 0) {
            size++;
            tail = next;
            next = tail->next();
        }
        PacketBatchVector* b = make_from_tailed_list(head,size);
        b->set_tail(tail);
        return b;
    }

    /**
     * Make a batch composed of a single packet
     */
    inline static PacketBatchVector* make_from_packet(Packet* p) {
        if (!p) return 0;
        PacketBatchVector* b = make_packet_batch_from_pool();
        b->append_packet(p);
        return b;
    }

#if !CLICK_LINUXMODULE
    static PacketBatchVector *make_batch(unsigned char *data, uint16_t count, uint16_t *length,
                    Packet::buffer_destructor_type destructor,
                                    void* argument = (void*) 0, const bool clear=true) CLICK_WARN_UNUSED_RESULT;
#endif

    /**
     * Return the first packet of this batch
     */
    inline Packet* begin() {
        return first();
    }

    /**
     * Return the last packet of this batch
     */
    inline Packet* end() {
        return tail();
    }

    /**
     * Kill all packets in the batch
     */
    inline void kill();

    /**
     * Release the memory of the batch, but don't kill the packets in it.
     */
     inline void soft_kill() {
        FOR_EACH_PACKET_SAFE_VEC(this,p) {
            pop_at(i);
        }

        batch_pool->releaseMemory(this);
    }


    /**
     * Clone the batch
     */
    inline PacketBatchVector* clone_batch() {
        PacketBatchVector* batch = make_packet_batch_from_pool();
        FOR_EACH_PACKET_VEC(this, p) {
            Packet* q = p->clone();
            batch->append_packet(q);
        }
        return batch;
    }

#if HAVE_BATCH && HAVE_CLICK_PACKET_POOL
    /**
     * Kill all packets of batch of unshared packets. Using this on unshared packets is very dangerous !
     */
    void recycle_batch(bool is_data);

    void fast_kill();
    void fast_kill_nonatomic();
#else
    inline void fast_kill() {
        kill();
    }

    void fast_kill_nonatomic() {
        kill();
    }
#endif
};

/**
 * Recycle a whole batch
 */
inline void PacketBatchVector::kill() {
    FOR_EACH_PACKET_SAFE_VEC(this,p) {
        p->kill();
        pop_at(i);
    }

    batch_pool->releaseMemory(this);
}

#if HAVE_BATCH_RECYCLE
#define BATCH_RECYCLE_START_VEC() \
	WritablePacket* head_packet = 0;\
	WritablePacket* head_data = 0;\
	WritablePacket* last_packet = 0;\
	WritablePacket* last_data = 0;\
	unsigned int n_packet = 0;\
	unsigned int n_data = 0;

#define BATCH_RECYCLE_ADD_PACKET_VEC(p) {\
	if (head_packet == 0) {\
		head_packet = static_cast<WritablePacket*>(p);\
		last_packet = static_cast<WritablePacket*>(p);\
	} else {\
		last_packet->set_next(p);\
		last_packet = static_cast<WritablePacket*>(p);\
	}\
	n_packet++;}

#define BATCH_RECYCLE_ADD_DATA_PACKET_VEC(p) {\
	if (head_data == 0) {\
		head_data = static_cast<WritablePacket*>(p);\
		last_data = static_cast<WritablePacket*>(p);\
	} else {\
		last_data->set_next(p);\
		last_data = static_cast<WritablePacket*>(p);\
	}\
	n_data++;}

#define BATCH_RECYCLE_PACKET_VEC(p) {\
			if (p->shared()) {\
				p->kill();\
			} else {\
				BATCH_RECYCLE_UNKNOWN_PACKET_VEC(p);\
			}\
		}

#define BATCH_RECYCLE_PACKET_NONATOMIC_VEC(p) {\
            if (p->shared_nonatomic()) {\
                p->kill_nonatomic();\
            } else {\
                BATCH_RECYCLE_UNKNOWN_PACKET_VEC(p);\
            }\
        }

#if HAVE_DPDK_PACKET_POOL
#define BATCH_RECYCLE_UNKNOWN_PACKET_VEC(p) {\
	if (p->data_packet() == 0 && (DPDKDevice::is_dpdk_packet(p)) && p->buffer() != 0) {\
		BATCH_RECYCLE_ADD_DATA_PACKET_VEC(p);\
	} else {\
		BATCH_RECYCLE_ADD_PACKET_VEC(p);}}
#elif !defined(CLICK_NOINDIRECT)
#define BATCH_RECYCLE_UNKNOWN_PACKET_VEC(p) {\
	if (p->data_packet() == 0 && p->buffer_destructor() == 0 && p->buffer() != 0) {\
		BATCH_RECYCLE_ADD_DATA_PACKET_VEC(p);\
	} else {\
	    BATCH_RECYCLE_ADD_PACKET_VEC(p);}}
#else
#define BATCH_RECYCLE_UNKNOWN_PACKET_VEC(p) {\
	if (p->buffer_destructor() == 0 && p->buffer() != 0) {\
		BATCH_RECYCLE_ADD_DATA_PACKET_VEC(p);\
	} else {\
	    BATCH_RECYCLE_ADD_PACKET_VEC(p);}}
#endif

#define BATCH_RECYCLE_END_VEC() \
	if (last_packet) {\
		last_packet->set_next(0);\
		PacketBatchVector::make_from_simple_list(head_packet,last_packet,n_packet)->recycle_batch(false);\
	}\
	if (last_data) {\
		last_data->set_next(0);\
		PacketBatchVector::make_from_simple_list(head_data,last_data,n_data)->recycle_batch(true);\
	}
#else
#define BATCH_RECYCLE_START_VEC() {}
#define BATCH_RECYCLE_END_VEC() {}
#define BATCH_RECYCLE_PACKET_VEC(p) {p->kill();}
#define BATCH_RECYCLE_PACKET_NONATOMIC_VEC(p) {p->kill_nonatomic();}
#endif

/**
 * Use the context of the element to know if the NONATOMIC or ATOMIC version should be called
 */
#define BATCH_RECYCLE_PACKET_CONTEXT_VEC(p) {\
            if (likely(is_fullpush())) {\
                BATCH_RECYCLE_PACKET_NONATOMIC_VEC(p);\
            } else {\
                BATCH_RECYCLE_PACKET_VEC(p);\
            }\
        }

/**
 * Set of functions to efficiently create a batch.
 */
#define BATCH_CREATE_INIT_VEC(batch) \
        PacketBatchVector* batch = PacketBatchVector::make_packet_batch_from_pool(); \
        int batch ## count = 0; \
        Packet* batch ## last = 0;
#define BATCH_CREATE_APPEND_VEC(batch,p) \
        batch->append_packet(p);
#define BATCH_CREATE_FINISH_VEC(batch) (void)batch //not needed, but keep for backward compatibility

typedef Packet::PacketType PacketType;

#if HAVE_BATCH && HAVE_CLICK_PACKET_POOL
/**
 * Recycle a whole batch of unshared packets of the same type
 *
 * @precond No packet are shared
 */
inline void PacketBatchVector::recycle_batch(bool is_data) {
    if (is_data) {
        WritablePacket::recycle_data_batch((WritablePacket*)this->first(),tail(),count());
    } else {
        WritablePacket::recycle_packet_batch((WritablePacket*)this->first(),tail(),count());
    }
}
#endif

CLICK_ENDDECLS
#endif
