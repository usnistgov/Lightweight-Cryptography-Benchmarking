/*
 *  Copyright 2019 Mitsubishi Electric Corporation. All Rights Reserved.
 *
 *  SAEAES
 *
 *  version 1.0.0
 *  February 2019
 */

#ifndef __SAEAES_H__
#define __SAEAES_H__

#include "api.h"

#define AES_BLOCK 16
#define SAEAES_R   8

#ifdef saeaes128a64t64v1
#define SAEAES_R1 8
#endif
#ifdef saeaes128a64t128v1
#define SAEAES_R1 8
#endif
#ifdef saeaes128a120t64v1
#define SAEAES_R1 15
#endif
#ifdef saeaes128a120t128v1
#define SAEAES_R1 15
#endif
#ifdef saeaes192a64t64v1
#define SAEAES_R1 8
#endif
#ifdef saeaes192a64t128v1
#define SAEAES_R1 8
#endif
#ifdef saeaes192a120t128v1
#define SAEAES_R1 15
#endif
#ifdef saeaes256a64t64v1
#define SAEAES_R1 8
#endif
#ifdef saeaes256a64t128v1
#define SAEAES_R1 8
#endif
#ifdef saeaes256a120t128v1
#define SAEAES_R1 15
#endif

#if CRYPTO_KEYBYTES==16
#define AES_EKEY 44
#elif CRYPTO_KEYBYTES==24
#define AES_EKEY 52
#elif CRYPTO_KEYBYTES==32
#define AES_EKEY 60
#endif

#define GetU32( x ) ((unsigned long)*(x+0)^(unsigned long)*(x+1)<<8^(unsigned long)*(x+2)<<16^(unsigned long)*(x+3)<<24)
#define PutU32( a, b ) {\
    *(b+0)=(unsigned char)(a & 0xff);\
    *(b+1)=(unsigned char)(a>>8 & 0xff);\
    *(b+2)=(unsigned char)(a>>16 & 0xff);\
    *(b+3)=(unsigned char)(a>>24);\
}

void AesKey( const unsigned char*, unsigned long* );
void AesEnc( unsigned char*, const unsigned long* );
#endif

