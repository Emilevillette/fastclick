#ifndef CLICK_PACKETBATCH_HH
#define CLICK_PACKETBATCH_HH

#include <click/config.h>


#if HAVE_VECTOR
    #include <click/packetbatchvector.hh>
    typedef PacketBatchVector PacketBatch;

    #define FOR_EACH_PACKET(batch,p) FOR_EACH_PACKET_VEC(batch->first(),p)
    #define FOR_EACH_PACKET_SAFE(batch,p) FOR_EACH_PACKET_SAFE_VEC(batch->first(),p)
    #define EXECUTE_FOR_EACH_PACKET(fnt,batch) EXECUTE_FOR_EACH_PACKET_VEC(fnt,batch)
    #define EXECUTE_FOR_EACH_PACKET_UNTIL_DO(fnt,batch,on_stop) EXECUTE_FOR_EACH_PACKET_UNTIL_DO_VEC(fnt,batch,on_stop)
    #define EXECUTE_FOR_EACH_PACKET_UNTIL(fnt,batch) EXECUTE_FOR_EACH_PACKET_UNTIL_VEC(fnt,batch)
    #define EXECUTE_FOR_EACH_PACKET_UNTIL_DROP(fnt,batch) EXECUTE_FOR_EACH_PACKET_UNTIL_DROP_VEC(fnt,batch)
    #define EXECUTE_FOR_EACH_PACKET_DROPPABLE(fnt,batch,on_drop) EXECUTE_FOR_EACH_PACKET_DROPPABLE_VEC(fnt,batch,on_drop)
    #define EXECUTE_FOR_EACH_PACKET_DROP_LIST(fnt,batch,drop_list) EXECUTE_FOR_EACH_PACKET_DROP_LIST_VEC(fnt,batch,drop_list)
    #define EXECUTE_FOR_EACH_PACKET_SPLITTABLE(fnt,batch,on_drop,on_flush) EXECUTE_FOR_EACH_PACKET_SPLITTABLE_VEC(fnt,batch,on_drop,on_flush)
    #define EXECUTE_FOR_EACH_PACKET_ADD(fnt,batch) EXECUTE_FOR_EACH_PACKET_ADD_VEC(fnt,batch)
    #define CLASSIFY_EACH_PACKET(nbatches,cep_batch,fnt,on_finish) CLASSIFY_EACH_PACKET_VEC(nbatches,cep_batch,fnt,on_finish)
    #define CLASSIFY_EACH_PACKET_IGNORE(nbatches, fnt, cep_batch, on_finish) CLASSIFY_EACH_PACKET_IGNORE_VEC(nbatches, fnt, cep_batch, on_finish)
    #define MAKE_BATCH(fnt,head, max) MAKE_BATCH_VEC(fnt,head, max)

#else
    #include <click/packetbatchlinkedlist.hh>
    typedef PacketBatchLinkedList PacketBatch;

    //TODO

#endif

#endif // CLICK_PACKETBATCH_HH