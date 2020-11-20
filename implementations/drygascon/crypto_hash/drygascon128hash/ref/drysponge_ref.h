/**
DrySponge
Sebastien Riou, January 6th 2019
c99 ref implementation meant to fit in the supercop framework
*/
#ifndef __DRYSPONGE_H__
#define __DRYSPONGE_H__

#include "drysponge_common.h"

#ifndef DRYSPONGE_DBG_EN
#define DRYSPONGE_DBG_EN 0
#endif

typedef struct DRYSPONGE_struct_t {
    uint8_t c[DRYSPONGE_CAPACITYSIZE];
    uint8_t x[DRYSPONGE_XSIZE];
    uint8_t r[DRYSPONGE_BLOCKSIZE];
    uint8_t *obuf;
    uint64_t fcnt;
    #ifdef DRYSPONGE_EXT
    DRYSPONGE_EXT_t ext;
    #endif
    unsigned int rounds;
} DRYSPONGE_t;

#include "drysponge_dbg_support.h"

static void DRYSPONGE_g(
    DRYSPONGE_t *const ctx
){
    #if DRYSPONGE_DBG_EN
        bytes_utiles_printf("   G entry %lu:\n",ctx->fcnt);
        DRYSPONGE_print_state(ctx);
    #endif
    ctx->fcnt++;
    memset(ctx->r,0,DRYSPONGE_BLOCKSIZE);
    for(unsigned int j = 0;j<ctx->rounds;j++){
        #if DRYSPONGE_DBG_EN >= DRYSPONGE_DBG_ROUND_IO
            bytes_utiles_printf("   CoreRound entry %d:\n",j);
            DRYSPONGE_print_state(ctx);
        #endif
        DRYSPONGE_CoreRound(ctx,j);
        for(unsigned int k=0;k<DRYSPONGE_ACCUMULATE_FACTOR;k++){
            uint8_t *cpart = ctx->c+4*k*DRYSPONGE_BLOCKSIZE32;
            for(unsigned int i=0;i<DRYSPONGE_BLOCKSIZE;i++){
                ctx->r[i]^=cpart[(i+k*4)%DRYSPONGE_BLOCKSIZE];
            }
        }
    }
}

static void DRYSPONGE_f(
    DRYSPONGE_t *const ctx,
    const uint8_t *const i
){
    #if DRYSPONGE_DBG_EN
        bytes_utiles_printf("   F entry %lu:\n",ctx->fcnt);
        DRYSPONGE_print_state(ctx);
        print_bytes_sep("       I = ",i,DRYSPONGE_BLOCKSIZE,"\n","");
    #endif
    DRYSPONGE_MixPhase(ctx,i);
    #if DRYSPONGE_DBG_EN >= DRYSPONGE_DBG_ROUND_IO
        bytes_utiles_printf("   After mix phase:\n");
        DRYSPONGE_print_state(ctx);
    #endif
    DRYSPONGE_g(ctx);
}

static void DRYSPONGE_set_key(
    DRYSPONGE_t *const ctx,
    const uint8_t *const key,
    const unsigned int keylen
){
    assert(DRYSPONGE_KEYSIZE<=keylen);
    const unsigned int midkeysize = DRYSPONGE_KEYSIZE+DRYSPONGE_XSIZE;
    const unsigned int fullkeysize = DRYSPONGE_CAPACITYSIZE+DRYSPONGE_XSIZE;
    uint8_t*x = (uint8_t*)ctx->x;
    if(fullkeysize == keylen){//all words for x assumed to be different
        memcpy(ctx->c,key,DRYSPONGE_CAPACITYSIZE);
        memcpy(ctx->x,key+DRYSPONGE_CAPACITYSIZE,DRYSPONGE_XSIZE);
    } else {
        for(unsigned int i=0;i<DRYSPONGE_CAPACITYSIZE;i++){
            ctx->c[i] = key[i%DRYSPONGE_KEYSIZE];
        }
        if(midkeysize == keylen){//all words for x assumed to be different
            for(unsigned int i=0;i<DRYSPONGE_XSIZE;i++){
                x[i] = key[DRYSPONGE_KEYSIZE+i];
            }
        } else {
            assert(DRYSPONGE_KEYSIZE==keylen);
            DRYSPONGE_CoreRound(ctx,0);
            //need to fixup x such that all words are different
            unsigned int modified=1;
            while(modified){
                modified=0;
                for(unsigned int i=0;i<DRYSPONGE_XSIZE32-1;i++){
                    for(unsigned int j=i+1;j<DRYSPONGE_XSIZE32;j++){
                        uint32_t ci,cj;
                        DRYSPONGE_load32(&ci,ctx->c+i*sizeof(uint32_t));
                        DRYSPONGE_load32(&cj,ctx->c+j*sizeof(uint32_t));
                        if(ci==cj){
                            DRYSPONGE_CoreRound(ctx,0);
                            modified=1;
                            break;
                        }
                    }
                    if(modified) break;
                }
            }
            memcpy(ctx->x,ctx->c,DRYSPONGE_XSIZE);
            memcpy(ctx->c,key,DRYSPONGE_XSIZE);
        }
    }
    //sanity check: all words in x shall be different
    for(unsigned int i=0;i<DRYSPONGE_XSIZE32-1;i++){
        for(unsigned int j=i+1;j<DRYSPONGE_XSIZE32;j++){
            uint32_t xi,xj;
            DRYSPONGE_load32(&xi,ctx->x+i*sizeof(uint32_t));
            DRYSPONGE_load32(&xj,ctx->x+j*sizeof(uint32_t));
            assert(xi!=xj);
        }
    }
}

static unsigned int DRYSPONGE_padding(
    const uint8_t *const ib,//one block of input or less
    uintptr_t iblen,
    uint8_t *const ob//exactly one block
){
    assert(iblen<=DRYSPONGE_BLOCKSIZE);
    memcpy(ob,ib,iblen);
    unsigned int padded = 0;
    if(iblen<DRYSPONGE_BLOCKSIZE){
        ob[iblen] = 0x01;
        if(iblen+1<DRYSPONGE_BLOCKSIZE){
            memset(ob+iblen+1,0,DRYSPONGE_BLOCKSIZE-iblen-1);
        }
        padded = 1;
    }
    return padded;
}

static void DRYSPONGE_absorb_only(
    DRYSPONGE_t *const ctx,
    const uint8_t *const ad,
    size_t alen,
    unsigned int ds,
    unsigned int finalize
){
    const uint8_t *iad = ad;
    size_t a = (alen + DRYSPONGE_BLOCKSIZE - 1) / DRYSPONGE_BLOCKSIZE;
    if(a){
        for(size_t i = 0; i<a-1; i++){//process all blocks except last one
            DRYSPONGE_f(ctx,iad);
            iad+=DRYSPONGE_BLOCKSIZE;
        }
    }
    uint8_t last_block[DRYSPONGE_BLOCKSIZE];
    uintptr_t remaining = ad+alen-iad;
    uint8_t apad = DRYSPONGE_padding(iad,remaining,last_block);
    DRYSPONGE_DomainSeparator(DRYSPONGE_EXT_ARG,DRYSPONGE_DSINFO(apad,ds,finalize));
    DRYSPONGE_f(ctx,last_block);
}

static void DRYSPONGE_squeez_only(
    DRYSPONGE_t *const ctx,
    uint8_t *out,
    unsigned int remaining
){
    while(remaining){
        unsigned int len = remaining > DRYSPONGE_BLOCKSIZE ? DRYSPONGE_BLOCKSIZE : remaining;
        memcpy(out,ctx->r,len);
        out+=len;
        remaining-=len;
        if(remaining){
            DRYSPONGE_g(ctx);
        }
    }
}

static void DRYSPONGE_init_ctx(
    DRYSPONGE_t *const ctx
){
    #ifdef DRYSPONGE_EXT
    memset(DRYSPONGE_EXT_ARG,0,sizeof(DRYSPONGE_EXT_t));
    #endif
    ctx->fcnt=0;
    memset(ctx->r,0x00,DRYSPONGE_BLOCKSIZE);
}

static void DRYSPONGE_hash(
    const uint8_t *const message,
    const size_t mlen,
    uint8_t *const digest
){
    DRYSPONGE_t ctx_storage;
    DRYSPONGE_t *const ctx = &ctx_storage;
    DRYSPONGE_init_ctx(ctx);
    ctx->rounds=DRYSPONGE_ROUNDS;
    #if DRYSPONGE_DBG_EN
        bytes_utiles_printf("Hashing %lu bytes message: ",mlen);
        print_bytes_sep("",message,mlen,"\n","");
    #endif
    const uint8_t CST_H[] = {
        0x24,0x3f,0x6a,0x88,0x85,0xa3,0x08,0xd3,
        0x13,0x19,0x8a,0x2e,0x03,0x70,0x73,0x44,
        0xa4,0x09,0x38,0x22,0x29,0x9f,0x31,0xd0,
        0x08,0x2e,0xfa,0x98,0xec,0x4e,0x6c,0x89,
        0x45,0x28,0x21,0xe6,0x38,0xd0,0x13,0x77,
        0xbe,0x54,0x66,0xcf,0x34,0xe9,0x0c,0x6c,
        0xc0,0xac,0x29,0xb7,0xc9,0x7c,0x50,0xdd,
        0x3f,0x84,0xd5,0xb5,0xb5,0x47,0x09,0x17,
        0x92,0x16,0xd5,0xd9,0x89,0x79,0xfb,0x1b,
        0xd1,0x31,0x0b,0xa6,0x98,0xdf,0xb5,0xac,
        0x2f,0xfd,0x72,0xdb,0xd0,0x1a,0xdf,0xb7,
        0xb8,0xe1,0xaf,0xed,0x6a,0x26,0x7e,0x96,
        0xba,0x7c,0x90,0x45,0xf1,0x2c,0x7f,0x99,
        0x24,0xa1,0x99,0x47,0xb3,0x91,0x6c,0xf7,
        0x08,0x01,0xf2,0xe2,0x85,0x8e,0xfc,0x16,
        0x63,0x69,0x20,0xd8,0x71,0x57,0x4e,0x69,
    };
    DRYSPONGE_set_key(ctx,CST_H,DRYSPONGE_KEYSIZE+DRYSPONGE_XSIZE);
    DRYSPONGE_absorb_only(ctx,message,mlen,DRYSPONGE_DS,1);
    DRYSPONGE_squeez_only(ctx,digest,DRYSPONGE_DIGESTSIZE);
    #if DRYSPONGE_DBG_EN
        bytes_utiles_printf("   Final state:\n");
        DRYSPONGE_print_state(ctx);
        print_bytes_sep("   Digest: ",digest,DRYSPONGE_DIGESTSIZE,"\n","");
    #endif
}

static void DRYSPONGE_init(
    DRYSPONGE_t *const ctx,
    const uint8_t *const key,
    const unsigned int klen,
    const uint8_t *const nonce,
    uint8_t *out_buffer,//output buffer
    unsigned int finalize
){
    DRYSPONGE_init_ctx(ctx);
    ctx->rounds=DRYSPONGE_ROUNDS;
    DRYSPONGE_set_key(ctx,key,klen);
    ctx->obuf = out_buffer;
    ctx->rounds=DRYSPONGE_INIT_ROUNDS;
    #if DRYSPONGE_NONCESIZE>DRYSPONGE_BLOCKSIZE
        assert(0==(DRYSPONGE_NONCESIZE%DRYSPONGE_BLOCKSIZE));
        unsigned int nloops = DRYSPONGE_DIVUP(DRYSPONGE_NONCESIZE,DRYSPONGE_BLOCKSIZE);
        for(unsigned int i=0;i<nloops-1;i++){
            DRYSPONGE_f(ctx,nonce+i*DRYSPONGE_BLOCKSIZE);
        }
        DRYSPONGE_DomainSeparator(DRYSPONGE_EXT_ARG,DRYSPONGE_DSINFO(0,DRYSPONGE_DD,finalize));
        DRYSPONGE_f(ctx,nonce+(nloops-1)*DRYSPONGE_BLOCKSIZE);
    #else
        uint8_t block[DRYSPONGE_BLOCKSIZE] = {0};
        memcpy(block,nonce,DRYSPONGE_NONCESIZE);
        DRYSPONGE_DomainSeparator(DRYSPONGE_EXT_ARG,DRYSPONGE_DSINFO(0,DRYSPONGE_DD,finalize));
        DRYSPONGE_f(ctx,block);
    #endif
    ctx->rounds=DRYSPONGE_ROUNDS;
}

static void DRYSPONGE_enc_core(
    DRYSPONGE_t *const ctx,
    const uint8_t *const ib//exactly one block of input
){
    DRYSPONGE_xor(ctx->r,ib,ctx->obuf);
    DRYSPONGE_f(ctx,ib);
    ctx->obuf+=DRYSPONGE_BLOCKSIZE;
}

static void DRYSPONGE_dec_core(
    DRYSPONGE_t *const ctx,
    const uint8_t *const ib//exactly one block of input
){
    DRYSPONGE_xor(ctx->r,ib,ctx->obuf);
    DRYSPONGE_f(ctx,ctx->obuf);
    ctx->obuf+=DRYSPONGE_BLOCKSIZE;
}

static void DRYSPONGE_enc(
    const uint8_t *const key,
    const unsigned int klen,
    const uint8_t *const nonce,
    const uint8_t *const message,
    const size_t mlen,
    const uint8_t * const ad,
    const size_t alen,
    uint8_t *ciphertext,
    size_t *clen
){
    const uint8_t *im = message;
    DRYSPONGE_t ctx_storage;
    DRYSPONGE_t *const ctx = &ctx_storage;
    unsigned int finalize = (mlen|alen) ? 0 : 1;
    DRYSPONGE_init(
        ctx,
        key,
        klen,
        nonce,
        ciphertext,
        finalize
    );
    if(alen){
        finalize = mlen ? 0 : 1;
        DRYSPONGE_absorb_only(ctx,ad,alen,DRYSPONGE_DA,finalize);
    }
    if(mlen){
        size_t m = (mlen + DRYSPONGE_BLOCKSIZE - 1) / DRYSPONGE_BLOCKSIZE;
        for(size_t i = 0; i<m-1; i++){//process all blocks except last one
            DRYSPONGE_enc_core(ctx,im);
            im+=DRYSPONGE_BLOCKSIZE;
        }
        uint8_t last_block[DRYSPONGE_BLOCKSIZE];
        unsigned int remaining = message+mlen-im;
        uint8_t mpad = DRYSPONGE_padding(im,remaining,last_block);
        DRYSPONGE_DomainSeparator(DRYSPONGE_EXT_ARG,DRYSPONGE_DSINFO(mpad,DRYSPONGE_DM,1));
        DRYSPONGE_enc_core(ctx,last_block);//writing full block is fine since we still have the area reserved for the tag
        ctx->obuf = ciphertext + mlen;//fix the size
    }
    DRYSPONGE_squeez_only(ctx,ctx->obuf,DRYSPONGE_TAGSIZE);
    *clen = mlen+DRYSPONGE_TAGSIZE;
    #if DRYSPONGE_DBG_EN
        bytes_utiles_printf("   Final state:\n");
        DRYSPONGE_print_state(ctx);
        print_bytes_sep("   CipherText: ",ciphertext,*clen,"\n","");
    #endif
}

//WARNING the function writes plaintext into "message" before checking the tag.
//It is the responsability of the caller to ensure that the "message" buffer is
//not accessible by anything until this function has return.
static int DRYSPONGE_dec(
    const uint8_t *const key,
    const unsigned int klen,
    const uint8_t *const nonce,
    const uint8_t *const ciphertext,
    const size_t clen,
    const uint8_t * const ad,
    const size_t alen,
    uint8_t *message
){
    if(clen<DRYSPONGE_TAGSIZE) return -1;
    size_t mlen = clen - DRYSPONGE_TAGSIZE;
    const uint8_t *im = ciphertext;
    DRYSPONGE_t ctx_storage;
    DRYSPONGE_t *const ctx = &ctx_storage;
    unsigned int finalize = (mlen|alen) ? 0 : 1;
    DRYSPONGE_init(
        ctx,
        key,
        klen,
        nonce,
        message,
        finalize
    );
    if(alen){
        finalize = mlen ? 0 : 1;
        DRYSPONGE_absorb_only(ctx,ad,alen,DRYSPONGE_DA,finalize);
    }
    if(mlen){
        size_t m = (mlen + DRYSPONGE_BLOCKSIZE - 1) / DRYSPONGE_BLOCKSIZE;
        for(size_t i = 0; i<m-1; i++){//process all blocks except last one
            DRYSPONGE_dec_core(ctx,im);
            im+=DRYSPONGE_BLOCKSIZE;
        }
        uint8_t last_block[DRYSPONGE_BLOCKSIZE];
        unsigned int remaining = ciphertext+mlen-im;
        memcpy(last_block,im,remaining);
        DRYSPONGE_xor(ctx->r,last_block,last_block);
        uint8_t mpad = DRYSPONGE_padding(last_block,remaining,last_block);
        im+=remaining;
        DRYSPONGE_DomainSeparator(DRYSPONGE_EXT_ARG,DRYSPONGE_DSINFO(mpad,DRYSPONGE_DM,1));
        memcpy(ctx->obuf,last_block,remaining);
        DRYSPONGE_f(ctx,last_block);
    }
    uint8_t tag[DRYSPONGE_TAGSIZE];
    DRYSPONGE_squeez_only(ctx,tag,DRYSPONGE_TAGSIZE);
    DRYSPONGE_DBG(print_bytes_sep("expected tag=",im,DRYSPONGE_TAGSIZE,"\n",""));
    DRYSPONGE_DBG(print_bytes_sep("computed tag=",tag,DRYSPONGE_TAGSIZE,"\n",""));
    if(memcmp(tag,im,DRYSPONGE_TAGSIZE)){
        memset(message,0,mlen);//erase all output
        return ~DRYSPONGE_PASS;
    }
    return DRYSPONGE_PASS;
}
#endif
