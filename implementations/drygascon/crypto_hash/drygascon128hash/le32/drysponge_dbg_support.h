#ifndef __DRYSPONGE_DBG_SUPPORT_H__
#define __DRYSPONGE_DBG_SUPPORT_H__

#define DRYSPONGE_DBG_NONE 0
#define DRYSPONGE_DBG_ALG_IO 1
#define DRYSPONGE_DBG_F_IO 2
#define DRYSPONGE_DBG_ROUND_IO 3
#define DRYSPONGE_DBG_FULL 4

#if DRYSPONGE_DBG_EN
    #define DRYSPONGE_DBG(a) a;
#else
    #define DRYSPONGE_DBG(a)
#endif


#if DRYSPONGE_DBG_EN
#include <assert.h>
#include <stdio.h>
#include "bytes_utils.h"
static void DRYSPONGE_print_state(
    DRYSPONGE_t *const ctx
){
    (void)xor_bytes;
    (void)println_128;
    (void)bytes_utils_remove_unused_warnings;
    unsigned int linesize = 32;
    if(linesize<DRYSPONGE_BLOCKSIZE) linesize = DRYSPONGE_BLOCKSIZE;
    unsigned int remaining = DRYSPONGE_CAPACITYSIZE;
    const uint8_t*const c = (const uint8_t*const)ctx->c;
    for(unsigned int i=0;i<DRYSPONGE_DIVUP(DRYSPONGE_CAPACITYSIZE,linesize);i++){
        bytes_utiles_printf(     "   C[%2u] = ",i);
        unsigned int len = linesize < remaining ? linesize : remaining;
        print_bytes_sep("",c+i*linesize,len,"\n","");
        remaining -= len;
    }
    remaining = DRYSPONGE_XSIZE;
    const uint8_t*const x = (const uint8_t*const)ctx->x;
    for(unsigned int i=0;i<DRYSPONGE_DIVUP(DRYSPONGE_XSIZE,linesize);i++){
        bytes_utiles_printf(     "   X[%2u] = ",i);
        unsigned int len = linesize < remaining ? linesize : remaining;
        print_bytes_sep("",x+i*linesize,len,"\n","");
        remaining -= len;
    }
    print_bytes_sep("       R = ",ctx->r,DRYSPONGE_BLOCKSIZE,"\n","");
}
#endif

#endif
