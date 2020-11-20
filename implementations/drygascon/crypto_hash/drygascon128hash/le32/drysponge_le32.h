/**
DrySponge
Sebastien Riou, January 6th 2019
c99 little endian 32 bit implementation meant to fit in the supercop framework

Note: although this is faster than the ref implementation we noticed that it is
still several times slower compared to what can be done with assembly.
*/
#ifndef __DRYSPONGE_H__
#define __DRYSPONGE_H__

#include "drysponge_common.h"

//assume 32bit alignement is enough to access uint64_t since we target 32 bit CPU
#define ALIGN64 4
//#define ALIGN64 8

#ifndef DRYSPONGE_DBG_EN
#define DRYSPONGE_DBG_EN 0
#endif

typedef struct DRYSPONGE_struct_t {
    uint64_t c[DRYSPONGE_CAPACITYSIZE64];
    uint64_t r[DRYSPONGE_BLOCKSIZE64];
    uint64_t x[DRYSPONGE_XSIZE64];
    uint8_t *obuf;
    uint64_t fcnt;
    #ifdef DRYSPONGE_EXT
    DRYSPONGE_EXT_t ext;
    #endif
    unsigned int rounds;
} DRYSPONGE_t;

#include "drysponge_dbg_support.h"

static void DRYSPONGE_xor64(
    const uint64_t *const a,//exactly one block of input
    const uint64_t *const b,
    uint64_t *const y
){
    for(unsigned int i=0;i<DRYSPONGE_BLOCKSIZE64;i++){
        y[i] = a[i] ^ b[i];
    }
}

//static void DRYSPONGE_xor32(
//    const uint32_t *const a,//exactly one block of input
//    const uint32_t *const b,
//    uint32_t *const y
//){
//    for(unsigned int i=0;i<DRYSPONGE_BLOCKSIZE32;i++){
//        y[i] = a[i] ^ b[i];
//    }
//}

#ifdef DRYSPONGE_OPT_G
void drygascon128_g(uint64_t* x, uint32_t rounds);
static void DRYSPONGE_g(
    DRYSPONGE_t *const ctx
){
    DRYSPONGE_OPT_G((uint64_t*)&(ctx->c),ctx->rounds);
}
#else
static void DRYSPONGE_g(
    DRYSPONGE_t *const ctx
){
    #if DRYSPONGE_DBG_EN
        printf("   G entry %lu:\n",ctx->fcnt);
        DRYSPONGE_print_state(ctx);
    #endif
    ctx->fcnt++;
    DRYSPONGE_xor64(ctx->r,ctx->r,ctx->r);//r=0
    for(unsigned int j = 0;j<ctx->rounds;j++){
        #if DRYSPONGE_DBG_EN >= DRYSPONGE_DBG_ROUND_IO
            printf("   CoreRound entry %d:\n",j);
            DRYSPONGE_print_state(ctx);
        #endif
        DRYSPONGE_CoreRound(ctx,j);
        uint32_t r32[DRYSPONGE_BLOCKSIZE32];
        uint32_t cpart[DRYSPONGE_BLOCKSIZE32];
	    memcpy(r32,ctx->r,sizeof(r32));
        for(unsigned int k=0;k<DRYSPONGE_ACCUMULATE_FACTOR;k++){
            memcpy(cpart,ctx->c+k*DRYSPONGE_BLOCKSIZE64,sizeof(cpart));
            for(unsigned int i=0;i<DRYSPONGE_BLOCKSIZE32;i++){
                r32[i]^=cpart[(i+k)%DRYSPONGE_BLOCKSIZE32];
            }
        }
        memcpy(ctx->r,r32,sizeof(r32));
    }
}
#endif

#ifdef DRYSPONGE_OPT_F
static void DRYSPONGE_DomainSeparator(
    DRYSPONGE_EXT_t *const ext,
    unsigned int dsinfo
){
    *ext = dsinfo;
}
void drygascon128_f(uint64_t* x, uint32_t*in,uint32_t ds,uint32_t rounds);
static void DRYSPONGE_f(
    DRYSPONGE_t *const ctx,
    const uint8_t *const i
){
    DRYSPONGE_OPT_F((uint64_t*)&(ctx->c),(uint32_t*)i,(uint32_t)ctx->ext,ctx->rounds);
    ctx->ext=0;
}
#else
static void DRYSPONGE_f(
    DRYSPONGE_t *const ctx,
    const uint8_t *const i
){
    #if DRYSPONGE_DBG_EN
        printf("   F entry %lu:\n",ctx->fcnt);
        DRYSPONGE_print_state(ctx);
        print_bytes_sep("       I = ",i,DRYSPONGE_BLOCKSIZE,"\n","");
    #endif
    DRYSPONGE_MixPhase(ctx,i);
    #if DRYSPONGE_DBG_EN >= DRYSPONGE_DBG_ROUND_IO
        printf("   After mix phase:\n");
        DRYSPONGE_print_state(ctx);
    #endif
    DRYSPONGE_g(ctx);
}
#endif

static void DRYSPONGE_set_key(
    DRYSPONGE_t *const ctx,
    const uint8_t *const key,
    const unsigned int keylen
){
    assert(DRYSPONGE_KEYSIZE<=keylen);
    const unsigned int midkeysize = DRYSPONGE_KEYSIZE+DRYSPONGE_XSIZE;
    const unsigned int fullkeysize = DRYSPONGE_CAPACITYSIZE+DRYSPONGE_XSIZE;
    if(DRYSPONGE_KEYSIZE!=keylen){//all words for x assumed to be different
        if(fullkeysize == keylen){
            memcpy(ctx->c,key,DRYSPONGE_CAPACITYSIZE);
            memcpy(ctx->x,key+DRYSPONGE_CAPACITYSIZE,DRYSPONGE_XSIZE);
        } else {
            uint8_t c[DRYSPONGE_CAPACITYSIZE];
            uint8_t x[DRYSPONGE_XSIZE];
            assert(midkeysize==keylen);
            for(unsigned int i=0;i<DRYSPONGE_CAPACITYSIZE;i++){
                c[i] = key[i%DRYSPONGE_KEYSIZE];
            }
            for(unsigned int i=0;i<DRYSPONGE_XSIZE;i++){
                x[i] = key[DRYSPONGE_KEYSIZE+i];
            }
            memcpy(ctx->c,c,DRYSPONGE_CAPACITYSIZE);
            memcpy(ctx->x,x,DRYSPONGE_XSIZE);
        }
    }else{
        uint8_t c[DRYSPONGE_CAPACITYSIZE];
        for(unsigned int i=0;i<DRYSPONGE_CAPACITYSIZE;i++){
            c[i] = key[i%DRYSPONGE_KEYSIZE];
        }
        memcpy(ctx->c,c,DRYSPONGE_CAPACITYSIZE);
        DRYSPONGE_CoreRound(ctx,0);
        //need to fixup x such that all words are different
        unsigned int modified=1;
        while(modified){
            uint32_t c32[DRYSPONGE_CAPACITYSIZE32];
            memcpy(c32,ctx->c,DRYSPONGE_CAPACITYSIZE);
            modified=0;
            for(unsigned int i=0;i<DRYSPONGE_XSIZE32-1;i++){
                for(unsigned int j=i+1;j<DRYSPONGE_XSIZE32;j++){
                    if(c32[i]==c32[j]){
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
    uint32_t x32[DRYSPONGE_XSIZE32];// = (uint32_t *const)ctx->x;
    memcpy(x32,ctx->x,DRYSPONGE_XSIZE);
    //sanity check: all words in x shall be different
    for(unsigned int i=0;i<DRYSPONGE_XSIZE32-1;i++){
        for(unsigned int j=i+1;j<DRYSPONGE_XSIZE32;j++){
            assert(x32[i]!=x32[j]);
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
        printf("Hashing %lu bytes message: ",mlen);
        print_bytes_sep("",message,mlen,"\n","");
    #endif
    const uint64_t CST_H[] = {
        0xd308a385886a3f24,
        0x447370032e8a1913,
        0xd0319f29223809a4,
        0x896c4eec98fa2e08,
        0x7713d038e6212845,
        0x6c0ce934cf6654be,
        0xdd507cc9b729acc0,
        0x170947b5b5d5843f,
        0x1bfb7989d9d51692,
        0xacb5df98a60b31d1,
        0xb7df1ad0db72fd2f,
        0x967e266aedafe1b8,
        0x997f2cf145907cba,
        0xf76c91b34799a124,
        0x16fc8e85e2f20108,
        0x694e5771d8206963,
    };
    DRYSPONGE_set_key(ctx,(const uint8_t*)CST_H,DRYSPONGE_KEYSIZE+DRYSPONGE_XSIZE);
    DRYSPONGE_absorb_only(ctx,message,mlen,DRYSPONGE_DS,1);
    DRYSPONGE_squeez_only(ctx,digest,DRYSPONGE_DIGESTSIZE);
    #if DRYSPONGE_DBG_EN
        printf("   Final state:\n");
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
    DRYSPONGE_DomainSeparator(DRYSPONGE_EXT_ARG,DRYSPONGE_DSINFO(0,DRYSPONGE_DD,finalize));
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
    const uint64_t *const ib//exactly one block of input
){

    DRYSPONGE_xor((uint8_t *)ctx->r,(uint8_t *)ib,ctx->obuf);
    DRYSPONGE_f(ctx,(uint8_t *)ib);
    ctx->obuf+=DRYSPONGE_BLOCKSIZE;
}

static void DRYSPONGE_enc_core_aligned(
    DRYSPONGE_t *const ctx,
    const uint64_t *const ib//exactly one block of input
){
    assert((((uintptr_t)ctx->obuf)%8) == 0);
    DRYSPONGE_xor64(ctx->r,ib,(uint64_t*const)ctx->obuf);
    DRYSPONGE_f(ctx,(uint8_t *)ib);
    ctx->obuf+=DRYSPONGE_BLOCKSIZE;
}

static const uint8_t* DRYSPONGE_enc_blocks(
    DRYSPONGE_t *const ctx,
    const uint8_t *im,//whole message
    size_t m
){
    (void)DRYSPONGE_load32;
    (void)DRYSPONGE_store32;
    (void)DRYSPONGE_load64;
    (void)DRYSPONGE_store64;
    uint64_t buf64[DRYSPONGE_BLOCKSIZE64];
    const uint64_t *ib64;
    #if DRYSPONGE_BLOCKSIZE % ALIGN64
        unsigned int input_aligned = 0;
        unsigned int output_aligned = 0;
    #else
        unsigned int input_aligned = 0==(((uintptr_t)im)%ALIGN64);
        unsigned int output_aligned = 0==(((uintptr_t)ctx->obuf)%ALIGN64);
    #endif
    if(input_aligned && output_aligned){
        for(size_t i = 0; i<m; i++){
            ib64 = (const uint64_t*)im;
            DRYSPONGE_enc_core_aligned(ctx,ib64);
            im+=DRYSPONGE_BLOCKSIZE;
        }
    }else{
        ib64 = buf64;
        for(size_t i = 0; i<m; i++){
            memcpy(buf64,im,DRYSPONGE_BLOCKSIZE);
            DRYSPONGE_enc_core(ctx,ib64);//input is now aligned but output may not
            im+=DRYSPONGE_BLOCKSIZE;
        }
    }
    return im;
}

static void DRYSPONGE_dec_core(
    DRYSPONGE_t *const ctx,
    const uint8_t *const ib//exactly one block of input
){
    DRYSPONGE_xor((uint8_t *)ctx->r,ib,ctx->obuf);
    DRYSPONGE_f(ctx,ctx->obuf);
    ctx->obuf+=DRYSPONGE_BLOCKSIZE;
}

static void DRYSPONGE_dec_core_aligned(
    DRYSPONGE_t *const ctx,
    const uint64_t *const ib//exactly one block of input
){
    DRYSPONGE_xor64(ctx->r,ib,(uint64_t*const)ctx->obuf);
    DRYSPONGE_f(ctx,ctx->obuf);
    ctx->obuf+=DRYSPONGE_BLOCKSIZE;
}

static const uint8_t* DRYSPONGE_dec_blocks(
    DRYSPONGE_t *const ctx,
    const uint8_t *im,//whole message
    size_t m
){
    const uint64_t *ib64;
    #if DRYSPONGE_BLOCKSIZE % ALIGN64
        unsigned int input_aligned = 0;
        unsigned int output_aligned = 0;
    #else
        unsigned int input_aligned = 0==(((uintptr_t)im)%ALIGN64);
        unsigned int output_aligned = 0==(((uintptr_t)ctx->obuf)%ALIGN64);
    #endif
    if(input_aligned && output_aligned){
        for(size_t i = 0; i<m; i++){
            ib64 = (const uint64_t*)im;
            DRYSPONGE_dec_core_aligned(ctx,ib64);
            im+=DRYSPONGE_BLOCKSIZE;
        }
    }else{
        for(size_t i = 0; i<m; i++){
            DRYSPONGE_dec_core(ctx,im);
            im+=DRYSPONGE_BLOCKSIZE;
        }
    }
    return im;
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
        im=DRYSPONGE_enc_blocks(ctx,im,m-1);//process all blocks except the last one
        uint64_t last_block64[DRYSPONGE_BLOCKSIZE64];
        uint8_t*last_block=(uint8_t*)last_block64;
        unsigned int remaining = message+mlen-im;
        uint8_t mpad = DRYSPONGE_padding(im,remaining,last_block);
        DRYSPONGE_DomainSeparator(DRYSPONGE_EXT_ARG,DRYSPONGE_DSINFO(mpad,DRYSPONGE_DM,1));
        DRYSPONGE_enc_core(ctx,last_block64);//writing full block is fine since we still have the area reserved for the tag
        ctx->obuf = ciphertext + mlen;//fix the size
    }
    DRYSPONGE_squeez_only(ctx,ctx->obuf,DRYSPONGE_TAGSIZE);
    *clen = mlen+DRYSPONGE_TAGSIZE;
    #if DRYSPONGE_DBG_EN
        printf("   Final state:\n");
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
        im=DRYSPONGE_dec_blocks(ctx,im,m-1);
        uint64_t last_block64[DRYSPONGE_BLOCKSIZE64];
        uint8_t*last_block=(uint8_t*)last_block64;
        unsigned int remaining = ciphertext+mlen-im;
        memcpy(last_block,im,remaining);
        DRYSPONGE_xor64(ctx->r,last_block64,last_block64);
        uint8_t mpad = DRYSPONGE_padding(last_block,remaining,last_block);
        im+=remaining;
        DRYSPONGE_DomainSeparator(DRYSPONGE_EXT_ARG,DRYSPONGE_DSINFO(mpad,DRYSPONGE_DM,1));
        memcpy(ctx->obuf,last_block,remaining);
        DRYSPONGE_f(ctx,last_block);
    }
    uint64_t tag64[DRYSPONGE_TAGSIZE64];
    uint8_t*tag = (uint8_t*)tag64;
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
