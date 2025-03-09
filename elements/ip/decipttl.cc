/*
 * decipttl.{cc,hh} -- element decrements IP packet's time-to-live
 * Eddie Kohler, Robert Morris
 *
 * Computational batching support
 * by Georgios Katsikas
 *
 * Copyright (c) 1999-2000 Massachusetts Institute of Technology
 * Copyright (c) 2008 Meraki, Inc.
 * Copyright (c) 2016 KTH Royal Institute of Technology
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
#include "decipttl.hh"
#include <click/glue.hh>
#include <click/args.hh>
#include <clicknet/ip.h>

#include <immintrin.h>
CLICK_DECLS

DecIPTTL::DecIPTTL()
    : _active(true), _multicast(true)
{
    _drops = 0;
}

DecIPTTL::~DecIPTTL()
{
}

int
DecIPTTL::configure(Vector<String> &conf, ErrorHandler *errh)
{
    return Args(conf, this, errh)
	.read("ACTIVE", _active)
	.read("MULTICAST", _multicast).complete();
}

Packet *
DecIPTTL::simple_action(Packet *p)
{
    assert(p->has_network_header());
    if (!_active)
	return p;
    const click_ip *ip_in = p->ip_header();
    if (!_multicast && IPAddress(ip_in->ip_dst).is_multicast())
	return p;

    if (ip_in->ip_ttl <= 1) {
	++_drops;
	checked_output_push(1, p);
	return 0;
    } else {
	WritablePacket *q = p->uniqueify();
	if (!q)
	    return 0;
	click_ip *ip = q->ip_header();
	--ip->ip_ttl;

	// 19.Aug.1999 - incrementally update IP checksum as suggested by SOSP
	// reviewers, according to RFC1141, as updated by RFC1624.
	// new_sum = ~(~old_sum + ~old_halfword + new_halfword)
	//         = ~(~old_sum + ~old_halfword + (old_halfword - 0x0100))
	//         = ~(~old_sum + ~old_halfword + old_halfword + ~0x0100)
	//         = ~(~old_sum + ~0 + ~0x0100)
	//         = ~(~old_sum + 0xFEFF)
	unsigned long sum = (~ntohs(ip->ip_sum) & 0xFFFF) + 0xFEFF;
	ip->ip_sum = ~htons(sum + (sum >> 16));

	return q;
    }
}


#if HAVE_BATCH
PacketBatch *
DecIPTTL::simple_action_batch(PacketBatch *batch)
{
  #if HAVE_AVX2 && HAVE_VECTOR
	simple_action_avx(batch, [](Packet *){});
  #else
    EXECUTE_FOR_EACH_PACKET_DROPPABLE(DecIPTTL::simple_action, batch, [](Packet *){});
  #endif
    return batch;
}
#endif

#if HAVE_AVX2 && HAVE_VECTOR

void DecIPTTL::simple_action_avx(PacketBatch *& batch, std::function<void(Packet *)> on_drop) {

  // If the element is not active, return, batch is not modified
    if(!_active) {
        return;
    }

    int count = batch->count();

    PacketBatch *new_batch = PacketBatch::make_packet_batch_from_pool();

    uint8_t dst_ttl[16] = {0};
    uint16_t dst_checksum[16] = {0};

    // Since we are working with a checksum of 16 bits, we have 256/16 = 16 packets per iteration
    for(int iter = 0; iter < count; iter = iter + 16) {
	    uint16_t idxs[16] = {0};
	    uint16_t idxs_size = 0;
	    uint16_t idxs_curr = 0;
	    uint16_t drop_idxs[16] = {0};

        for (int i = 0; i < 16; i++) {
            Packet *q = batch->at(iter + i);
			// In case there are not 16 packets remaining
            if(!q) {
				continue;
			}
            // Check if the packet has a network header
			assert(q->has_network_header());

            // If the condition is true, then the packet should be treated
            if(_multicast || !IPAddress(q->ip_header()->ip_dst).is_multicast()) {
                idxs[idxs_size]  = iter + i;
                idxs_size++;
			}
            dst_ttl[i] = q->ip_header()->ip_ttl;
            // If the TTL is less than or equal to 1, then the packet should be dropped
            if(dst_ttl[i] <= 1) {
                drop_idxs[iter + i] = 1;
                ++_drops;
                checked_output_push(1, q);
                on_drop(q);
            }
            // perform ntohs before avx to ensure the operation is done in the correct order
			dst_checksum[i] = ~ntohs(q->ip_header()->ip_sum);
		}

        // Decrement the TTL
        __m256i ttl = _mm256_loadu_si256((__m256i *) dst_ttl);
        __m256i one = _mm256_set1_epi8(1);
        ttl = _mm256_sub_epi8(ttl, one);
        _mm256_storeu_si256((__m256i *) dst_ttl, ttl);

        // Calculate the new checksum
        __m256i sum = _mm256_loadu_si256((__m256i *) dst_checksum);
        __m256i ffff = _mm256_set1_epi16(0xFFFF);
        sum = _mm256_and_si256(sum, ffff);
        __m256i feff = _mm256_set1_epi16(0xFEFF);
        sum = _mm256_add_epi16(sum, feff);
        sum = _mm256_add_epi16(sum,  _mm256_srli_epi16(sum,16));
        _mm256_storeu_si256((__m256i *) dst_checksum, sum);

        for(int i = 0 ; i < 16 ; i++) {
          	// If the packet was not dropped, then it should be updated
        	if(drop_idxs[iter + i] == 0) {
                // If the packet is not multicast, then it should be updated
                if(idxs[idxs_curr] == iter + i) {
                    WritablePacket *r = batch->at(iter + i)->uniqueify();
                    if(!r) {
                        on_drop(batch->at(iter + i));
                    } else {
                        click_ip *ip = r->ip_header();
                        ip->ip_ttl = dst_ttl[i];
                        // Update the checksum to the correct order
                        ip->ip_sum = ~htons(dst_checksum[i]);
                        new_batch->append_packet(r);
                    }
                    idxs_curr++;
                }
            }
        }
    }

    // Replace the pointer reference to the new batch and soft kill (i.e. release packet pointers) the old batch
    PacketBatch *old_batch = batch;
    batch = new_batch;
    old_batch->soft_kill();

}

#endif

void
DecIPTTL::add_handlers()
{
    add_data_handlers("drops", Handler::OP_READ, &_drops);
    add_data_handlers("active", Handler::OP_READ | Handler::OP_WRITE | Handler::CHECKBOX, &_active);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(DecIPTTL)
ELEMENT_MT_SAFE(DecIPTTL)
