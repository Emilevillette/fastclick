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
#include <click/dpdkdevice.hh>

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
  #if HAVE_BATCH && HAVE_AVX512 && HAVE_VECTOR && HAVE_DPDK_PACKET_POOL
	simple_action_avx(batch, [](Packet *){});
  #else
    EXECUTE_FOR_EACH_PACKET_DROPPABLE(DecIPTTL::simple_action, batch, [](Packet *){});
  #endif
    return batch;
}
#endif

#if HAVE_BATCH && HAVE_AVX512 && HAVE_VECTOR && HAVE_DPDK_PACKET_POOL

#define TTL_OFFSET 374
#define CHECKSUM_OFFSET 376
#define PACKET_LENGTH 408
#define IP_DST_OFFSET 382

void DecIPTTL::simple_action_avx(PacketBatch *& batch, std::function<void(Packet *)> on_drop) {

  // If the element is not active, return, batch is not modified
    if(!_active) {
        return;
    }

    click_chatter("p %p\n", batch->at(0));
    click_chatter("ttl %p\n", &(batch->at(0)->ip_header()->ip_ttl));
    click_chatter("TTL VALUE %d", batch->at(0)->ip_header()->ip_ttl);
    click_chatter("checksum %p\n", &(batch->at(0)->ip_header()->ip_sum));
    click_chatter("checksum value %d", batch->at(0)->ip_header()->ip_sum);
    click_chatter("dst %p\n", &(batch->at(0)->ip_header()->ip_dst));


    int count = batch->count();

    uint8_t dst_ttl[16] = {0};
    uint16_t dst_checksum[16] = {0};

    // Since we are working with a checksum of 16 bits, we have 256/16 = 16 packets per iteration
    rte_mempool *mpool = DPDKDevice::get_mpool(0);

    for(int iter = 0; iter < count; iter = iter + 64) {
        int32_t offsets[16];
		batch->at_range_offset(offsets, iter, 16);

        __m512i indices = _mm512_loadu_si512((__m512i*)offsets);

        // compare the values in indices with 0, if they are equal, set the corresponding bit to 0, we will gather with this mask
        __mmask16 mask = _mm512_cmpneq_epi32_mask(indices, _mm512_set1_epi32(0));
		__mmask16 mask_multicast = mask;


        __m512i _mpool = _mm512_set1_epi32((uint64_t)mpool);
		indices = _mm512_add_epi32(indices, _mm512_set1_epi32(TTL_OFFSET));
        indices = _mm512_sub_epi32(indices, _mpool);


	    printf("Mask: 0b");
	    for (int i = 15; i >= 0; i--) {  // Print from MSB to LSB
	        printf("%d", (mask >> i) & 1);
	    }
	    printf("\n");

		click_chatter("offsets: %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d", offsets[0], offsets[1], offsets[2], offsets[3], offsets[4], offsets[5], offsets[6], offsets[7], offsets[8], offsets[9], offsets[10], offsets[11], offsets[12], offsets[13], offsets[14], offsets[15]);
		click_chatter("base: %p", DPDKDevice::get_mpool(0));

        __m512i ttl_mask = _mm512_set1_epi32(0xff000000);

        // Decrement the TTL
        __m512i ttl = _mm512_slli_epi32(_mm512_mask_i32gather_epi32(_mm512_set1_epi32(0), mask, indices, mpool, 1), 24);
		ttl = _mm512_and_si512(ttl, ttl_mask);
        ttl_mask = _mm512_srli_epi32(ttl_mask, 8);

        batch->at_range_offset(offsets, iter+16, 16);
		__m512i indices2 = _mm512_loadu_si512((__m512i*)offsets);
        mask = _mm512_cmpneq_epi32_mask(indices2, _mm512_set1_epi32(0));
        __mmask16 mask_multicast2 = mask;
        indices2 = _mm512_sub_epi32(indices2, _mpool);
        indices2 = _mm512_add_epi32(indices2, _mm512_set1_epi32(TTL_OFFSET));

        __m512i ttl2 = _mm512_slli_epi32(_mm512_mask_i32gather_epi32(_mm512_set1_epi32(0), mask, indices2, mpool, 1), 16);
       	ttl2 = _mm512_and_si512(ttl2, ttl_mask);
        ttl_mask = _mm512_srli_epi32(ttl_mask, 8);
        ttl = _mm512_or_si512(ttl, ttl2);

        batch->at_range_offset(offsets, iter+32, 16);
		__m512i indices3 = _mm512_loadu_si512((__m512i*)offsets);
        mask = _mm512_cmpneq_epi32_mask(indices3, _mm512_set1_epi32(0));
		__mmask16 mask_multicast3 = mask;
        indices3 = _mm512_sub_epi32(indices3, _mpool);
        indices3 = _mm512_add_epi32(indices3, _mm512_set1_epi32(TTL_OFFSET));

        ttl2 = _mm512_slli_epi32(_mm512_mask_i32gather_epi32(_mm512_set1_epi32(0), mask, indices3, mpool, 1), 8);
        ttl2 = _mm512_and_si512(ttl2, ttl_mask);
        ttl_mask = _mm512_srli_epi32(ttl_mask, 8);
        ttl = _mm512_or_si512(ttl, ttl2);

		batch->at_range_offset(offsets, iter+48, 16);
		__m512i indices4 = _mm512_loadu_si512((__m512i*)offsets);
        mask = _mm512_cmpneq_epi32_mask(indices4, _mm512_set1_epi32(0));
		__mmask16 mask_multicast4 = mask;
        indices4 = _mm512_sub_epi32(indices4, _mpool);
        indices4 = _mm512_add_epi32(indices4, _mm512_set1_epi32(TTL_OFFSET));

        ttl2 = _mm512_mask_i32gather_epi32(_mm512_set1_epi32(0), mask, indices4, mpool, 1);
        ttl2 = _mm512_and_si512(ttl2, ttl_mask);
		ttl = _mm512_or_si512(ttl, ttl2);

        __m512i one = _mm512_set1_epi8(1);
        ttl = _mm512_sub_epi8 (ttl, one);

        // Mask The TTL to drop packets with TTL > 1
        __mmask64 drop_mask = _mm512_cmpgt_epu8_mask(ttl, one);

        __m512i shuffle_mask;
        if(!_multicast) {
			__m512i mc_indices = _mm512_add_epi32(_mm512_sub_epi32(indices, _mm512_set1_epi32(TTL_OFFSET)), _mm512_set1_epi32(IP_DST_OFFSET));
			__m512i mc_indices2 = _mm512_add_epi32(_mm512_sub_epi32(indices2, _mm512_set1_epi32(TTL_OFFSET)), _mm512_set1_epi32(IP_DST_OFFSET));
			__m512i mc_indices3 = _mm512_add_epi32(_mm512_sub_epi32(indices3, _mm512_set1_epi32(TTL_OFFSET)), _mm512_set1_epi32(IP_DST_OFFSET));
			__m512i mc_indices4 = _mm512_add_epi32(_mm512_sub_epi32(indices4, _mm512_set1_epi32(TTL_OFFSET)), _mm512_set1_epi32(IP_DST_OFFSET));

            shuffle_mask = _mm512_set_epi8(7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8, 23, 22, 21, 20, 19, 18, 17, 16, 31, 30, 29, 28, 27, 26, 25, 24, 39, 38, 37, 36, 35, 34, 33, 32, 47, 46, 45, 44, 43, 42, 41, 40, 55, 54, 53, 52, 51, 50, 49, 48, 63, 62, 61, 60, 59, 58, 57, 56);

            __m512i dst_ip = _mm512_i32gather_epi32(mc_indices, mpool, 1);

            __m512i F = _mm512_set1_epi32(0xF0000000U);
            __m512i E = _mm512_set1_epi32(0xE0000000U);
            if(*(char *)&dst_ip == 1) {
				F = _mm512_shuffle_epi8(F, shuffle_mask);
				E = _mm512_shuffle_epi8(E, shuffle_mask);
			}

			mask_multicast = _mm512_cmpeq_epi32_mask(_mm512_and_si512(dst_ip, F), E);

			dst_ip = _mm512_i32gather_epi32(mc_indices2, mpool, 1);

			mask_multicast2 = _mm512_cmpeq_epi32_mask(_mm512_and_si512(dst_ip, F), E);

			dst_ip = _mm512_i32gather_epi32(mc_indices3, mpool, 1);

		    mask_multicast3 = _mm512_cmpeq_epi32_mask(_mm512_and_si512(dst_ip, F), E);

            dst_ip = _mm512_i32gather_epi32(mc_indices4, mpool, 1);

            mask_multicast4 = _mm512_cmpeq_epi32_mask(_mm512_and_si512(dst_ip, F), E);
        }

        // Store the new TTL
        __m512i gathered = _mm512_and_si512(_mm512_set1_epi32(0xFFFFFF00), _mm512_i32gather_epi32(indices, mpool, 1));
		gathered = _mm512_or_si512(gathered, _mm512_and_si512(_mm512_srli_epi32(ttl,24), _mm512_set1_epi32(0x00FF)));
        _mm512_mask_i32scatter_epi32(mpool, mask_multicast, indices, gathered, 1);

        click_chatter("TTL VALUE AFTER %d", batch->at(0)->ip_header()->ip_ttl);

		gathered = _mm512_and_si512(_mm512_set1_epi32(0xFFFFFF00), _mm512_i32gather_epi32(indices2, mpool, 1));
        gathered = _mm512_or_si512(gathered, _mm512_and_si512(_mm512_srli_epi32(ttl,16), _mm512_set1_epi32(0x00FF)));
        _mm512_mask_i32scatter_epi32(mpool, mask_multicast2, indices2, gathered, 1);

        gathered = _mm512_and_si512(_mm512_set1_epi32(0xFFFFFF00), _mm512_i32gather_epi32(indices3, mpool, 1));
        gathered = _mm512_or_si512(gathered, _mm512_and_si512(_mm512_srli_epi32(ttl,8), _mm512_set1_epi32(0x00FF)));
        _mm512_mask_i32scatter_epi32(mpool, mask_multicast3, indices3, gathered, 1);

        gathered = _mm512_and_si512(_mm512_set1_epi32(0xFFFFFF00), _mm512_i32gather_epi32(indices4, mpool, 1));
        gathered = _mm512_or_si512(gathered, _mm512_and_si512(ttl, _mm512_set1_epi32(0x00FF)));
        _mm512_mask_i32scatter_epi32(mpool, mask_multicast4, indices4, gathered, 1);

        __m512i checksum_indices = _mm512_add_epi32(_mm512_sub_epi32(indices, _mm512_set1_epi32(TTL_OFFSET)), _mm512_set1_epi32(CHECKSUM_OFFSET));
        __m512i checksum_indices2 = _mm512_add_epi32(_mm512_sub_epi32(indices2, _mm512_set1_epi32(TTL_OFFSET)), _mm512_set1_epi32(CHECKSUM_OFFSET));
        __m512i checksum_indices3 = _mm512_add_epi32(_mm512_sub_epi32(indices3, _mm512_set1_epi32(TTL_OFFSET)), _mm512_set1_epi32(CHECKSUM_OFFSET));
        __m512i checksum_indices4 = _mm512_add_epi32(_mm512_sub_epi32(indices4, _mm512_set1_epi32(TTL_OFFSET)), _mm512_set1_epi32(CHECKSUM_OFFSET));

        // similar to the TTL, we need to gather the checksums of the packets
        /*
        __m512i checksum = _mm512_slli_epi32(_mm512_mask_i32gather_epi32(_mm512_set1_epi32(0), mask_multicast,checksum_indices, mpool, 1), 16);
        __m512i checksum2 = _mm512_and_si512(_mm512_mask_i32gather_epi32(_mm512_set1_epi32(0), mask_multicast2, checksum_indices2, mpool, 1), _mm512_set1_epi32(0x0000FFFF));
        checksum = _mm512_or_si512(checksum, checksum2);

        checksum2 = _mm512_slli_epi32(_mm512_mask_i32gather_epi32(_mm512_set1_epi32(0), mask_multicast3, checksum_indices3, mpool, 1), 16);
        __m512i checksum3 = _mm512_and_si512(_mm512_mask_i32gather_epi32(_mm512_set1_epi32(0), mask_multicast4, checksum_indices4, mpool, 1), _mm512_set1_epi32(0x0000FFFF));
        checksum2 = _mm512_or_si512(checksum2, checksum3);
         */

        __m512i checksum = _mm512_and_si512(_mm512_mask_i32gather_epi32(_mm512_set1_epi32(0), mask_multicast, checksum_indices, mpool, 1), _mm512_set1_epi32(0x0000FFFF));
        __m512i checksum2 = _mm512_and_si512(_mm512_mask_i32gather_epi32(_mm512_set1_epi32(0), mask_multicast2, checksum_indices2, mpool, 1), _mm512_set1_epi32(0x0000FFFF));
        __m512i checksum3 = _mm512_and_si512(_mm512_mask_i32gather_epi32(_mm512_set1_epi32(0), mask_multicast3, checksum_indices3, mpool, 1), _mm512_set1_epi32(0x0000FFFF));
        __m512i checksum4 = _mm512_and_si512(_mm512_mask_i32gather_epi32(_mm512_set1_epi32(0), mask_multicast4, checksum_indices4, mpool, 1), _mm512_set1_epi32(0x0000FFFF));

        // https://stackoverflow.com/questions/12791864/c-program-to-check-little-vs-big-endian/12792301#12792301
        // https://stackoverflow.com/questions/4181951/how-to-check-whether-a-system-is-big-endian-or-little-endian
		// little endian if true

        int n = 1;

		if(*(char *)&n == 1) {
            click_chatter("little endian");
            // Since the checksum is stored in network byte order, and the system is little endian, we need to convert it to host byte order
			shuffle_mask = _mm512_set_epi8(4, 5, 6, 7, 0, 1, 2, 3, 12, 13, 14, 15, 8, 9, 10, 11, 20, 21, 22, 23, 16, 17, 18, 19, 28, 29, 30, 31, 24, 25, 26, 27, 36, 37, 38, 39, 32, 33, 34, 35, 44, 45, 46, 47, 40, 41, 42, 43, 52, 53, 54, 55, 48, 49, 50, 51, 60, 61, 62, 63, 56, 57, 58, 59);
			checksum = _mm512_shuffle_epi8(checksum, shuffle_mask);
			checksum2 = _mm512_shuffle_epi8(checksum2, shuffle_mask);
			checksum3 = _mm512_shuffle_epi8(checksum3, shuffle_mask);
			checksum4 = _mm512_shuffle_epi8(checksum4, shuffle_mask);
        }
        // Apply not operation to the checksum
        checksum = _mm512_xor_si512(checksum, _mm512_set1_epi32(0xFFFFFFFF));
        checksum2 = _mm512_xor_si512(checksum2, _mm512_set1_epi32(0xFFFFFFFF));
        checksum3 = _mm512_xor_si512(checksum3, _mm512_set1_epi32(0xFFFFFFFF));
        checksum4 = _mm512_xor_si512(checksum4, _mm512_set1_epi32(0xFFFFFFFF));

        // Calculate the new checksum
        __m512i ffff = _mm512_set1_epi16(0xFFFF);
        __m512i feff = _mm512_set1_epi16(0xFEFF);
        checksum = _mm512_and_si512(checksum, ffff);
        checksum = _mm512_add_epi16(checksum, feff);
        checksum = _mm512_add_epi16(checksum,  _mm512_srli_epi16(checksum,16));

        checksum2 = _mm512_and_si512(checksum2, ffff);
        checksum2 = _mm512_add_epi16(checksum2, feff);
        checksum2 = _mm512_add_epi16(checksum2,  _mm512_srli_epi16(checksum2,16));

        checksum3 = _mm512_and_si512(checksum3, ffff);
        checksum3 = _mm512_add_epi16(checksum3, feff);
        checksum3 = _mm512_add_epi16(checksum3,  _mm512_srli_epi16(checksum3,16));

        checksum4 = _mm512_and_si512(checksum4, ffff);
        checksum4 = _mm512_add_epi16(checksum4, feff);
        checksum4 = _mm512_add_epi16(checksum4,  _mm512_srli_epi16(checksum4,16));

        // Convert back to host byte order
        if(*(char *)&n == 1) {
            checksum = _mm512_shuffle_epi8(checksum, shuffle_mask);
            checksum2 = _mm512_shuffle_epi8(checksum2, shuffle_mask);
            checksum3 = _mm512_shuffle_epi8(checksum3, shuffle_mask);
            checksum4 = _mm512_shuffle_epi8(checksum4, shuffle_mask);
        }
        checksum = _mm512_xor_si512(checksum, _mm512_set1_epi32(0xFFFFFFFF));
        checksum2 = _mm512_xor_si512(checksum2, _mm512_set1_epi32(0xFFFFFFFF));
        checksum3 = _mm512_xor_si512(checksum3, _mm512_set1_epi32(0xFFFFFFFF));
        checksum4 = _mm512_xor_si512(checksum4, _mm512_set1_epi32(0xFFFFFFFF));

        // also store similar to the TTL
        gathered = _mm512_and_si512(_mm512_set1_epi32(0xFFFF0000), _mm512_mask_i32gather_epi32(_mm512_set1_epi32(0), mask_multicast, checksum_indices, mpool, 1));
        gathered = _mm512_or_si512(gathered, _mm512_and_si512(checksum, _mm512_set1_epi32(0xFFFF)));
        _mm512_mask_i32scatter_epi32(mpool, mask_multicast, checksum_indices, gathered, 1);

        click_chatter("checksum value after %d", batch->at(0)->ip_header()->ip_sum);

        gathered = _mm512_and_si512(_mm512_set1_epi32(0xFFFF0000), _mm512_mask_i32gather_epi32(_mm512_set1_epi32(0), mask_multicast2, checksum_indices2, mpool, 1));
        gathered = _mm512_or_si512(gathered, _mm512_and_si512(checksum2, _mm512_set1_epi32(0xFFFF)));
        _mm512_mask_i32scatter_epi32(mpool, mask_multicast2, checksum_indices2, gathered, 1);

        gathered = _mm512_and_si512(_mm512_set1_epi32(0xFFFF0000), _mm512_mask_i32gather_epi32(_mm512_set1_epi32(0), mask_multicast3, checksum_indices3, mpool, 1));
        gathered = _mm512_or_si512(gathered, _mm512_and_si512(checksum3, _mm512_set1_epi32(0xFFFF)));
        _mm512_mask_i32scatter_epi32(mpool, mask_multicast3, checksum_indices3, gathered, 1);

        gathered = _mm512_and_si512(_mm512_set1_epi32(0xFFFF0000), _mm512_mask_i32gather_epi32(_mm512_set1_epi32(0), mask_multicast4, checksum_indices4, mpool, 1));
        gathered = _mm512_or_si512(gathered, _mm512_and_si512(checksum4, _mm512_set1_epi32(0xFFFF)));
        _mm512_mask_i32scatter_epi32(mpool, mask_multicast4, checksum_indices4, gathered, 1);

        // check if the mask is equal to a vector of 1, then all the packets have TTL > 1.
        // If not, we need to check the TTL of each packet, and drop the ones with TTL <= 1
        if(drop_mask != 0xFFFFFFFFFFFFFFFFULL) {
        	// there are packets to drop !!
            int n_drops = 0;
            for(int i = 0; i < 64; i++) {
            	if((drop_mask & (1 << i)) == 0) {
            		// drop the packet
                    ++_drops;
					checked_output_push(1, batch->at(iter + i - n_drops));
            		on_drop(batch->at(iter + i - n_drops));
                    batch->pop_at_safe(iter + i - n_drops);
                    n_drops++;
            	}
            }
        }
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
