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
  #if HAVE_AVX512 && HAVE_VECTOR
	simple_action_avx(batch, [](Packet *){});
  #else
    EXECUTE_FOR_EACH_PACKET_DROPPABLE(DecIPTTL::simple_action, batch, [](Packet *){});
  #endif
    return batch;
}
#endif

#if HAVE_AVX512 && HAVE_VECTOR

#define TTL_OFFSET 386
#define CHECKSUM_OFFSET 378
#define PACKET_LENGTH 408
#define IP_DST_OFFSET 384

void DecIPTTL::simple_action_avx(PacketBatch *& batch, std::function<void(Packet *)> on_drop) {

  // If the element is not active, return, batch is not modified
    if(!_active) {
        return;
    }

    int count = batch->count();

    uint8_t dst_ttl[16] = {0};
    uint16_t dst_checksum[16] = {0};

    // Since we are working with a checksum of 16 bits, we have 256/16 = 16 packets per iteration
    for(int iter = 0; iter < count; iter = iter + 64) {
        __m512i indices = _mm512_set_epi32(15*PACKET_LENGTH + TTL_OFFSET, 14*PACKET_LENGTH + TTL_OFFSET,
                                           13*PACKET_LENGTH + TTL_OFFSET, 12*PACKET_LENGTH + TTL_OFFSET,
										   11*PACKET_LENGTH + TTL_OFFSET, 10*PACKET_LENGTH + TTL_OFFSET,
                                           9*PACKET_LENGTH + TTL_OFFSET, 8*PACKET_LENGTH + TTL_OFFSET,
                                           7*PACKET_LENGTH + TTL_OFFSET, 6*PACKET_LENGTH + TTL_OFFSET,
                                           5*PACKET_LENGTH + TTL_OFFSET, 4*PACKET_LENGTH + TTL_OFFSET,
                                           3*PACKET_LENGTH + TTL_OFFSET, 2*PACKET_LENGTH + TTL_OFFSET,
                                           1*PACKET_LENGTH + TTL_OFFSET, TTL_OFFSET);

        // Decrement the TTL
        //__m256i ttl = _mm256_loadu_si256((__m256i *) dst_ttl);
        __m512i ttl = _mm512_sll_epi32(_mm512_i32gather_epi32((const int*)((char*)batch->at(iter)), indices, 1), 24);
		__m512i ttl2 = _mm512_sll_epi32(_mm512_i32gather_epi32((const int*)((char*)batch->at(iter + 16)), indices, 1), 16);
        ttl = _mm512_or_si512(ttl, ttl2);

		ttl2 = _mm512_sll_epi32(_mm512_i32gather_epi32((const int*)((char*)batch->at(iter + 32)), indices, 1), 8);

        __m512i ttl3 = _mm512_i32gather_epi32((const int*)((char*)batch->at(iter + 48)), indices, 1);
        ttl2 = _mm512_or_si512(ttl2, ttl3);
        ttl = _mm512_or_si512(ttl, ttl2);

        __m512i one = _mm512_set1_epi8(1);
        ttl = _mm512_sub_epi8 (ttl, one);

        // Mask The TTL to drop packets with TTL <= 1
        __mmask64 mask = _mm512_cmpgt_epu8_mask(ttl, one);

        // Mask for multicast packets
        __m512i shuffle_mask;
        if(!_multicast) {
            indices = _mm512_set_epi32(15*PACKET_LENGTH + IP_DST_OFFSET, 14*PACKET_LENGTH + IP_DST_OFFSET,
                                       13*PACKET_LENGTH + IP_DST_OFFSET, 12*PACKET_LENGTH + IP_DST_OFFSET,
                                       11*PACKET_LENGTH + IP_DST_OFFSET, 10*PACKET_LENGTH + IP_DST_OFFSET,
                                       9*PACKET_LENGTH + IP_DST_OFFSET, 8*PACKET_LENGTH + IP_DST_OFFSET,
                                       7*PACKET_LENGTH + IP_DST_OFFSET, 6*PACKET_LENGTH + IP_DST_OFFSET,
                                       5*PACKET_LENGTH + IP_DST_OFFSET, 4*PACKET_LENGTH + IP_DST_OFFSET,
                                       3*PACKET_LENGTH + IP_DST_OFFSET, 2*PACKET_LENGTH + IP_DST_OFFSET,
                                       1*PACKET_LENGTH + IP_DST_OFFSET, IP_DST_OFFSET);
            __m512i dst_ip = _mm512_i32gather_epi32((const int*)((char*)batch->at(iter)), indices, 1);

            shuffle_mask = _mm512_set_epi8(7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8, 23, 22, 21, 20, 19, 18, 17, 16, 31, 30, 29, 28, 27, 26, 25, 24, 39, 38, 37, 36, 35, 34, 33, 32, 47, 46, 45, 44, 43, 42, 41, 40, 55, 54, 53, 52, 51, 50, 49, 48, 63, 62, 61, 60, 59, 58, 57, 56);

            _m512i F = _mm512_set1_epi32(0xF0000000U);
            _m512i E = _mm512_set1_epi32(0xE0000000U);
            if(*(char *)&dst_ip == 1) {
				F = _mm512_shuffle_epi8(F, shuffle_mask);
				E = _mm512_shuffle_epi8(E, shuffle_mask);
			}

			_mmask16 mask_multicast = _mm512_cmpeq_epi32_mask(_mm512_and_si512(dst_ip, F), E);

			dst_ip = _mm512_i32gather_epi32((const int*)((char*)batch->at(iter + 16)), indices, 1);

			_mmask16 mask_multicast2 = _mm512_cmpeq_epi32_mask(_mm512_and_si512(dst_ip, F), E);

			dst_ip = _mm512_i32gather_epi32((const int*)((char*)batch->at(iter + 32)), indices, 1);

		    _mmask16 mask_multicast3 = _mm512_cmpeq_epi32_mask(_mm512_and_si512(dst_ip, F), E);

            dst_ip = _mm512_i32gather_epi32((const int*)((char*)batch->at(iter + 48)), indices, 1);

            _mmask16 mask_multicast4 = _mm512_cmpeq_epi32_mask(_mm512_and_si512(dst_ip, F), E);
        }

        // Store the new TTL
        __m512i gathered = _mm512_and_si512(_mm512_set1_epi32(0xFFFFFFF0), _mm512_i32gather_epi32(indices, (const int*)((char*)batch->at(iter)), 1));
		gathered = _mm512_or_si512(gathered, _mm512_and_si512(ttl, _mm512_set1_epi32(0x00FF)));
        _mm512_mask_i32scatter_epi32((int*)((char*)batch->at(iter)), mask_multicast, indices, gathered, 1);

        //repeat for the rest of the packets
        gathered = _mm512_and_si512(_mm512_set1_epi32(0xFFFFFFF0), _mm512_i32gather_epi32(indices, (const int*)((char*)batch->at(iter + 16)), 1));
        gathered = _mm512_or_si512(gathered, _mm512_and_si512(_mm512_srl_epi32(ttl,8), _mm512_set1_epi32(0x00FF)));
        _mm512_mask_i32scatter_epi32((int*)((char*)batch->at(iter + 16)), mask_multicast2, indices, gathered, 1);

        gathered = _mm512_and_si512(_mm512_set1_epi32(0xFFFFFFF0), _mm512_i32gather_epi32(indices, (const int*)((char*)batch->at(iter + 32)), 1));
        gathered = _mm512_or_si512(gathered, _mm512_and_si512(_mm512_srl_epi32(ttl,16), _mm512_set1_epi32(0x00FF)));
        _mm512_mask_i32scatter_epi32((int*)((char*)batch->at(iter + 32)), mask_multicast3, indices, gathered, 1);

        gathered = _mm512_and_si512(_mm512_set1_epi32(0xFFFFFFF0), _mm512_i32gather_epi32(indices, (const int*)((char*)batch->at(iter + 48)), 1));
        gathered = _mm512_or_si512(gathered, _mm512_and_si512(_mm512_srl_epi32(ttl,24), _mm512_set1_epi32(0x00FF)));
        _mm512_mask_i32scatter_epi32((int*)((char*)batch->at(iter + 48)), mask_multicast4, indices, gathered, 1);

        // check if the mask is equal to a vector of 1, then all the packets have TTL > 1.
        // If not, we need to check the TTL of each packet, and drop the ones with TTL <= 1
        if(mask != 0xFFFFFFFFFFFFFFFFULL) {
        	// there are packets to drop !!
            for(int i = 0; i < 64; i++) {
            	if((mask & (1 << i)) == 0) {
            		// drop the packet
                    ++_drops;
					checked_output_push(1, batch->at(iter + i));
            		on_drop(batch->at(iter + i));
                    batch->pop_at_safe(iter + i);
            	}
            }
        }

        indices = _mm512_set_epi32(15*PACKET_LENGTH + CHECKSUM_OFFSET, 14*PACKET_LENGTH + CHECKSUM_OFFSET,
                                   13*PACKET_LENGTH + CHECKSUM_OFFSET, 12*PACKET_LENGTH + CHECKSUM_OFFSET,
                                   11*PACKET_LENGTH + CHECKSUM_OFFSET, 10*PACKET_LENGTH + CHECKSUM_OFFSET,
                                   9*PACKET_LENGTH + CHECKSUM_OFFSET, 8*PACKET_LENGTH + CHECKSUM_OFFSET,
                                   7*PACKET_LENGTH + CHECKSUM_OFFSET, 6*PACKET_LENGTH + CHECKSUM_OFFSET,
                                   5*PACKET_LENGTH + CHECKSUM_OFFSET, 4*PACKET_LENGTH + CHECKSUM_OFFSET,
                                   3*PACKET_LENGTH + CHECKSUM_OFFSET, 2*PACKET_LENGTH + CHECKSUM_OFFSET,
                                   1*PACKET_LENGTH + CHECKSUM_OFFSET, CHECKSUM_OFFSET);

        // similar to the TTL, we need to gather the checksums of the packets
        __m512i checksum = _mm512_sll_epi32(_mm512_i32gather_epi32((const int*)((char*)batch->at(iter)), indices, 1), 16);
        __m512i checksum2 = _mm512_and_si512(_mm512_i32gather_epi32((const int*)((char*)batch->at(iter + 16)), indices, 1), _mm512_set1_epi32(0x0000FFFF));
        checksum = _mm512_or_si512(checksum, checksum2);

        checksum2 = _mm512_sll_epi32(_mm512_i32gather_epi32((const int*)((char*)batch->at(iter + 32)), indices, 1), 16);
        __m512i checksum3 = _mm512_and_si512(_mm512_i32gather_epi32((const int*)((char*)batch->at(iter + 48)), indices, 1), _mm512_set1_epi32(0x0000FFFF));
        checksum2 = _mm512_or_si512(checksum2, checksum3);

        // https://stackoverflow.com/questions/12791864/c-program-to-check-little-vs-big-endian/12792301#12792301
        // https://stackoverflow.com/questions/4181951/how-to-check-whether-a-system-is-big-endian-or-little-endian
		// little endian if true

        int n = 1;

		if(*(char *)&n == 1) {
            // Since the checksum is stored in network byte order, and the system is little endian, we need to convert it to host byte order
			shuffle_mask = _mm512_set_epi8(3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12, 19, 18, 17, 16, 23, 22, 21, 20, 27, 26, 25, 24, 31, 30, 29, 28, 35, 34, 33, 32, 39, 38, 37, 36, 43, 42, 41, 40, 47, 46, 45, 44, 51, 50, 49, 48, 55, 54, 53, 52, 59, 58, 57, 56, 63, 62, 61, 60);
			checksum = _mm512_shuffle_epi8(checksum, shuffle_mask);
			checksum2 = _mm512_shuffle_epi8(checksum2, shuffle_mask);
        }
        // Apply not operation to the checksum
        checksum = _mm512_xor_si512(checksum, _mm512_set1_epi32(0xFFFFFFFF));
        checksum2 = _mm512_xor_si512(checksum2, _mm512_set1_epi32(0xFFFFFFFF));


        // Calculate the new checksum
        //__m512i sum = _mm512_loadu_si512((__m512i *) dst_checksum);
        __m512i ffff = _mm512_set1_epi16(0xFFFF);
        __m512i feff = _mm512_set1_epi16(0xFEFF);
        checksum = _mm512_and_si512(checksum, ffff);
        checksum = _mm512_add_epi16(checksum, feff);
        checksum = _mm512_add_epi16(checksum,  _mm512_srli_epi16(checksum,16));

        checksum2 = _mm512_and_si512(checksum2, ffff);
        checksum2 = _mm512_add_epi16(checksum2, feff);
        checksum2 = _mm512_add_epi16(checksum2,  _mm512_srli_epi16(checksum2,16));

        // Convert back to host byte order
        if(*(char *)&n == 1) {
            checksum = _mm512_shuffle_epi8(checksum, shuffle_mask);
            checksum2 = _mm512_shuffle_epi8(checksum2, shuffle_mask);
        }
        checksum = _mm512_xor_si512(checksum, _mm512_set1_epi32(0xFFFFFFFF));
        checksum2 = _mm512_xor_si512(checksum2, _mm512_set1_epi32(0xFFFFFFFF));

        // also store similar to the TTL
        gathered = _mm512_and_si512(_mm512_set1_epi32(0xFF00), _mm512_i32gather_epi32(indices, (const int*)((char*)batch->at(iter)), 1));
        gathered = _mm512_or_si512(gathered, _mm512_and_si512(checksum, _mm512_set1_epi32(0xFFFF)));
        _mm512_mask_i32scatter_epi32((int*)((char*)batch->at(iter)), mask_multicast, indices, gathered, 1);

        gathered = _mm512_and_si512(_mm512_set1_epi32(0xFF00), _mm512_i32gather_epi32(indices, (const int*)((char*)batch->at(iter + 16)), 1));
        gathered = _mm512_or_si512(gathered, _mm512_and_si512(_mm512_srl_epi32(checksum,16), _mm512_set1_epi32(0xFFFF)));
        _mm512_mask_i32scatter_epi32((int*)((char*)batch->at(iter + 16)), mask_multicast2, indices, gathered, 1);

        gathered = _mm512_and_si512(_mm512_set1_epi32(0xFF00), _mm512_i32gather_epi32(indices, (const int*)((char*)batch->at(iter + 32)), 1));
        gathered = _mm512_or_si512(gathered, _mm512_and_si512(checksum2, _mm512_set1_epi32(0xFFFF)));
        _mm512_mask_i32scatter_epi32((int*)((char*)batch->at(iter + 32)), mask_multicast3, indices, gathered, 1);

        gathered = _mm512_and_si512(_mm512_set1_epi32(0xFF00), _mm512_i32gather_epi32(indices, (const int*)((char*)batch->at(iter + 48)), 1));
        gathered = _mm512_or_si512(gathered, _mm512_and_si512(_mm512_srl_epi32(checksum2,16), _mm512_set1_epi32(0xFFFF)));
        _mm512_mask_i32scatter_epi32((int*)((char*)batch->at(iter + 48)), mask_multicast4, indices, gathered, 1);
    }

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
