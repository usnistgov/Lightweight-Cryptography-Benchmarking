#ifndef __DRYSPONGE_COMMON_H__
#define __DRYSPONGE_COMMON_H__

#ifndef DRYSPONGE_FUNC
#define DRYSPONGE_FUNC inline static
#endif

//convention:
//  width means length in bits
//  size means length in bytes

#include <stdint.h>
#include <string.h>
#include <assert.h>

#if DRYSPONGE_DBG_EN
#include "bytes_utils.h"
#endif

#define DRYSPONGE_PASS 0

#define DRYSPONGE_DS 2
#define DRYSPONGE_DD 1
#define DRYSPONGE_DA 2
#define DRYSPONGE_DM 3

#define DRYSPONGE_STATESIZE (DRYSPONGE_CAPACITYSIZE+DRYSPONGE_BLOCKSIZE)
#define DRYSPONGE_DIGESTSIZE (DRYSPONGE_KEYSIZE*2)
#define DRYSPONGE_TAGSIZE DRYSPONGE_KEYSIZE
#define DRYSPONGE_KEYMAXSIZE (DRYSPONGE_CAPACITYSIZE+DRYSPONGE_XSIZE)

#define DRYSPONGE_DIVUP(a,b) (((a)+(b)-1)/(b))
#define DRYSPONGE_ROTR32(x,n) (0xFFFFFFFF & (((x)>>(n))|((x)<<(0x1F & (32-(n))))))
#define DRYSPONGE_ROTR64(x,n) (0xFFFFFFFFFFFFFFFF & (((x)>>(n))|((x)<<(0x3F & (64-(n))))))

#define DRYSPONGE_STATESIZE32 DRYSPONGE_DIVUP(DRYSPONGE_STATESIZE,4)
#define DRYSPONGE_CE_SIZE32 DRYSPONGE_DIVUP(DRYSPONGE_CE_SIZE,4)
#define DRYSPONGE_BLOCKSIZE32 DRYSPONGE_DIVUP(DRYSPONGE_BLOCKSIZE,4)
#define DRYSPONGE_CAPACITYSIZE32 DRYSPONGE_DIVUP(DRYSPONGE_CAPACITYSIZE,4)
#define DRYSPONGE_XSIZE32 DRYSPONGE_DIVUP(DRYSPONGE_XSIZE,4)
#define DRYSPONGE_KEYSIZE32 DRYSPONGE_DIVUP(DRYSPONGE_KEYSIZE,4)

#define DRYSPONGE_STATESIZE64 DRYSPONGE_DIVUP(DRYSPONGE_STATESIZE,8)
#define DRYSPONGE_CE_SIZE64 DRYSPONGE_DIVUP(DRYSPONGE_CE_SIZE,8)
#define DRYSPONGE_BLOCKSIZE64 DRYSPONGE_DIVUP(DRYSPONGE_BLOCKSIZE,8)
#define DRYSPONGE_CAPACITYSIZE64 DRYSPONGE_DIVUP(DRYSPONGE_CAPACITYSIZE,8)
#define DRYSPONGE_XSIZE64 DRYSPONGE_DIVUP(DRYSPONGE_XSIZE,8)
#define DRYSPONGE_KEYSIZE64 DRYSPONGE_DIVUP(DRYSPONGE_KEYSIZE,8)
#define DRYSPONGE_TAGSIZE64 DRYSPONGE_DIVUP(DRYSPONGE_TAGSIZE,8)
#define DRYSPONGE_KEYMAXSIZE64 DRYSPONGE_DIVUP(DRYSPONGE_KEYMAXSIZE,8)
#define DRYSPONGE_NONCESIZE64 DRYSPONGE_DIVUP(DRYSPONGE_NONCESIZE,8)

#if DRYSPONGE_NONCESIZE < 12
    #error "DRYSPONGE_NONCESIZE < 12"
#endif

#if DRYSPONGE_KEYSIZE < 16
    #error "DRYSPONGE_KEYSIZE < 16"
#endif

#if DRYSPONGE_DIGESTSIZE < 2*DRYSPONGE_KEYSIZE
    #error "DRYSPONGE_DIGESTSIZE < 2*DRYSPONGE_KEYSIZE"
#endif

#if DRYSPONGE_ACCUMULATE_FACTOR > ((DRYSPONGE_CAPACITYSIZE/4)/DRYSPONGE_BLOCKSIZE32)
    #error "DRYSPONGE_ACCUMULATE_FACTOR > ((DRYSPONGE_CAPACITYSIZE/4)/DRYSPONGE_BLOCKSIZE32)"
#endif

#ifdef DRYSPONGE_EXT
#define DRYSPONGE_EXT_ARG (&(ctx->ext))
#else
#define DRYSPONGE_EXT_ARG 0
#endif

DRYSPONGE_FUNC unsigned int DRYSPONGE_DSINFO(unsigned int padded, unsigned int domain, unsigned int finalize){
    #if DRYSPONGE_DBG_EN
        bytes_utiles_printf("   Adding DS: padded=%d, domain=%u, finalize=%d\n",padded,domain,finalize);
    #endif
    return padded+(finalize<<1)+(domain<<2);
}

DRYSPONGE_FUNC uint32_t DRYSPONGE_rotr32(uint32_t x, unsigned int n){
    assert(n<32);
    return DRYSPONGE_ROTR32(x,n);
}

DRYSPONGE_FUNC uint64_t DRYSPONGE_rotr64(uint64_t x, unsigned int n){
    assert(n<64);
    return DRYSPONGE_ROTR64(x,n);
}

DRYSPONGE_FUNC void DRYSPONGE_xor(
    const uint8_t *const a,//exactly one block of input
    const uint8_t *const b,
    uint8_t *const y
){
    for(unsigned int i=0;i<DRYSPONGE_BLOCKSIZE;i++){
        y[i] = a[i] ^ b[i];
    }
}

DRYSPONGE_FUNC void DRYSPONGE_load16(uint16_t* x, const uint8_t*const in) {
    *x = 0;
    for(unsigned int i = 0;i<2;i++){
        uint16_t b = in[i];
        *x = *x | (b<<(8*i));
    }
}

DRYSPONGE_FUNC void DRYSPONGE_load32(uint32_t* x, const uint8_t*const in) {
    *x = 0;
    for(unsigned int i = 0;i<4;i++){
        uint32_t b = in[i];
        *x = *x | (b<<(8*i));
    }
}

DRYSPONGE_FUNC void DRYSPONGE_store32(uint8_t* out, uint32_t x) {
    for(unsigned int i = 0;i<4;i++){
        out[i] = x >> (8*i);
    }
}

DRYSPONGE_FUNC void DRYSPONGE_load64(uint64_t* x, uint8_t* in) {
    *x = 0;
    for(unsigned int i = 0;i<8;i++){
        uint64_t b = in[i];
        *x = *x | (b<<(8*i));
    }
}

DRYSPONGE_FUNC void DRYSPONGE_store64(uint8_t* out, uint64_t x) {
    (void)DRYSPONGE_rotr32;
    (void)DRYSPONGE_load16;
    (void)DRYSPONGE_store32;
    for(unsigned int i = 0;i<8;i++){
        out[i] = x >> (8*i);
    }
}

#endif
