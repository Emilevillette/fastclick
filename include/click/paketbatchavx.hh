// -*- related-file-name: "../../lib/packetbatchavx.cc" -*-
#ifndef PAKETBATCHAVX_H
#define PAKETBATCHAVX_H

#if __AVX512F__
// Alias to avx512 implementation
#elif __AVX2__
// Alias to avx2 implementation
#endif

#endif //PAKETBATCHAVX_H
