/**
DryGascon_ref
Sebastien Riou, January 6th 2019
c99 ref implementation meant to fit in the supercop framework
*/
#ifndef __DRYGASCON_H__
#define __DRYGASCON_H__

#include <stdint.h>
typedef uint64_t DRYSPONGE_EXT_t;

#define DRYSPONGE_EXT

#include "drysponge_common.h"

//input width for one round of MixPhaseRound
#define DRYSPONGE_MPR_INPUT_MASK ((((uint64_t)1)<<DRYSPONGE_MPR_INPUT_WIDTH)-1)

#define DRYSPONGE_MPR_ROUNDS DRYSPONGE_DIVUP((DRYSPONGE_BLOCKSIZE*8)+4,DRYSPONGE_MPR_INPUT_WIDTH)

#if (DRYSPONGE_MPR_ROUNDS*DRYSPONGE_MPR_INPUT_WIDTH-4)<(DRYSPONGE_BLOCKSIZE*8)
    #error "(DRYSPONGE_MPR_ROUNDS*DRYSPONGE_MPR_INPUT_WIDTH-4)<(DRYSPONGE_BLOCKSIZE*8)"
#endif

#if DRYSPONGE_XSIZE32>16
    #error "DRYSPONGE_XSIZE32>16"
#endif

#if DRYSPONGE_XSIZE32 == 4
    #define DRYSPONGE_X_IDX_WIDTH 2
#endif

#if DRYSPONGE_MPR_INPUT_WIDTH == 10
    #define DRYSPONGE_RANK_BYTES 2
    typedef uint32_t permut_rank_t;
#endif
#if DRYSPONGE_MPR_INPUT_WIDTH == 18
    #define DRYSPONGE_RANK_BYTES 3
    typedef uint32_t permut_rank_t;
#endif

#define DRYSPONGE_X_IDX_MASK ((1<<DRYSPONGE_X_IDX_WIDTH)-1)

static void DRYSPONGE_DomainSeparator(
    DRYSPONGE_EXT_t *const ext,
    unsigned int dsinfo
){
    *ext = dsinfo;
    *ext = *ext<<((DRYSPONGE_BLOCKSIZE*8)%DRYSPONGE_MPR_INPUT_WIDTH);
}

static void DRYSPONGE_MixPhaseRound(
    DRYSPONGE_EXT_t ext,
    uint8_t *const c,
    uint8_t *const x,
    const uint8_t *const in,
    unsigned int bitidx,
    unsigned int insize
){
    unsigned int bi = bitidx/8;
    unsigned int shift = bitidx%8;
    permut_rank_t r=0;
    for(unsigned int i=0;i<DRYSPONGE_RANK_BYTES;i++){
        if(bi+i==insize) break;
        permut_rank_t b = in[bi+i];
        r|=b<<(8*i);
    }
    r = (r>>shift) & DRYSPONGE_MPR_INPUT_MASK;
    r^=ext;

    for(unsigned int j=0;j<DRYSPONGE_CAPACITYSIZE64;j++){
        unsigned int i = r & DRYSPONGE_X_IDX_MASK;
        r = r >> DRYSPONGE_X_IDX_WIDTH;
        for(unsigned int k=0;k<4;k++){
            c[j*8+k]^=x[i*4+k];
        }
    }
}

struct DRYSPONGE_struct_t;
typedef struct DRYSPONGE_struct_t DRYSPONGE_t ;
static void DRYSPONGE_MixPhase(
    DRYSPONGE_t *const ctx,
    const uint8_t *const in
);
static void DRYSPONGE_CoreRound(
    DRYSPONGE_t *const ctx,
    unsigned int r
);

#include "drysponge_ref.h"

static void DRYSPONGE_MixPhase(
    DRYSPONGE_t *const ctx,
    const uint8_t *const in
){
    unsigned int bitidx=0;
    #if DRYSPONGE_MPR_ROUNDS > 1
    for(unsigned int i=0;i<DRYSPONGE_MPR_ROUNDS-1;i++){
        DRYSPONGE_EXT_t ext=0;
        #if ((DRYSPONGE_MPR_ROUNDS-1)*(DRYSPONGE_MPR_INPUT_WIDTH))>(DRYSPONGE_BLOCKSIZE*8)
        if((ctx->ext) && (i==(DRYSPONGE_MPR_ROUNDS-2))){
            //DS info is split accross this block and the last one
            ext = ctx->ext;
            ctx->ext = ctx->ext >> ((DRYSPONGE_BLOCKSIZE*8)%DRYSPONGE_MPR_INPUT_WIDTH);
            ctx->ext = ctx->ext >> ((((DRYSPONGE_MPR_ROUNDS-1)*DRYSPONGE_MPR_INPUT_WIDTH))-(DRYSPONGE_BLOCKSIZE*8));
        }
        #endif
        DRYSPONGE_MixPhaseRound(ext,ctx->c,ctx->x,in,bitidx,DRYSPONGE_BLOCKSIZE);
        bitidx+=DRYSPONGE_MPR_INPUT_WIDTH;
        DRYSPONGE_CoreRound(ctx,0);
    }
    #endif
    DRYSPONGE_MixPhaseRound(ctx->ext,ctx->c,ctx->x,in,bitidx,DRYSPONGE_BLOCKSIZE);
    ctx->ext=0;
}

static void gascon_sboxes(uint64_t * const x, unsigned int nw){
    uint64_t t[DRYSPONGE_CAPACITYSIZE64];
    const unsigned int mid = nw/2;
    for(unsigned int i=0;i<mid+1;i++){
        unsigned int dst = 2*i;
        unsigned int src = (nw+dst-1) % nw;
        x[dst] ^= x[src];
    }
    for(unsigned int i=0;i<nw;i++){
        t[i] = (x[i] ^ 0xFFFFFFFFFFFFFFFFull) & x[(i+1)%nw];
    }
    for(unsigned int i=0;i<nw;i++){
        x[i] ^= t[(i+1)%nw];
    }
    for(unsigned int i=0;i<mid+1;i++){
        unsigned int src = 2*i;
        unsigned int dst = (src+1) % nw;
        x[dst] ^= x[src];
    }
    x[mid] ^= 0XFFFFFFFFFFFFFFFFull;
}

static uint64_t gascon_rotr64_interleaved(uint64_t in, unsigned int shift){
    uint32_t i[2];
    i[0] = in;
    i[1] = in>>32;
    unsigned int shift2 = shift/2;
    if(shift & 1){
        uint32_t tmp = DRYSPONGE_ROTR32(i[1],shift2);
        i[1] = DRYSPONGE_ROTR32(i[0],(shift2+1)%32);
        i[0] = tmp;
    }else{
        i[0] = DRYSPONGE_ROTR32(i[0],shift2);
        i[1] = DRYSPONGE_ROTR32(i[1],shift2);
    }
    in = i[1];
    in = (in<<32)|i[0];
    return in;
}

static void gascon_permutation_round(uint8_t* S, unsigned int round) {
    (void)DRYSPONGE_rotr64;
    uint64_t x[DRYSPONGE_CAPACITYSIZE64];
    for(unsigned int i=0;i<DRYSPONGE_CAPACITYSIZE64;i++){
        DRYSPONGE_load64(x+i, S + 8*i);
    }
    const unsigned int mid = DRYSPONGE_CAPACITYSIZE64 / 2;
    unsigned int rounds=12;
    const unsigned int r = 12-rounds+round;
    // addition of round constant
    x[mid] ^= ((0xfull - r) << 4) | r;
    // substitution layer
    gascon_sboxes(x,DRYSPONGE_CAPACITYSIZE64);
    // linear diffusion layer
    x[0] ^= gascon_rotr64_interleaved(x[0], 19) ^ gascon_rotr64_interleaved(x[0], 28);
    x[1] ^= gascon_rotr64_interleaved(x[1], 61) ^ gascon_rotr64_interleaved(x[1], 38);
    x[2] ^= gascon_rotr64_interleaved(x[2],  1) ^ gascon_rotr64_interleaved(x[2],  6);
    x[3] ^= gascon_rotr64_interleaved(x[3], 10) ^ gascon_rotr64_interleaved(x[3], 17);
    x[4] ^= gascon_rotr64_interleaved(x[4],  7) ^ gascon_rotr64_interleaved(x[4], 40);
    #if DRYSPONGE_CAPACITYSIZE64 > 5
        x[5] ^= gascon_rotr64_interleaved(x[5], 31) ^ gascon_rotr64_interleaved(x[5], 26);
        x[6] ^= gascon_rotr64_interleaved(x[6], 53) ^ gascon_rotr64_interleaved(x[6], 58);
        x[7] ^= gascon_rotr64_interleaved(x[7],  9) ^ gascon_rotr64_interleaved(x[7], 46);
        x[8] ^= gascon_rotr64_interleaved(x[8], 43) ^ gascon_rotr64_interleaved(x[8], 50);
    #endif
    for(unsigned int i=0;i<DRYSPONGE_CAPACITYSIZE64;i++){
        DRYSPONGE_store64(S + 8*i,x[i]);
    }
}

static void DRYSPONGE_CoreRound(
    DRYSPONGE_t *const ctx,
    unsigned int r
){
    gascon_permutation_round(ctx->c, r);
}



#endif
