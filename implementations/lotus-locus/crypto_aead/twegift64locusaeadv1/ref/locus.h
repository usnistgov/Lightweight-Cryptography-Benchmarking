#ifndef __LOCUS_H__
#define __LOCUS_H__

#include <string.h>
#include <stdlib.h>

/* 
 * No. of block cipher rounds to be used
 */ 
#define CRYPTO_BC_NUM_ROUNDS (28)

/* 
 * Block cipher's block size
 */ 
#define CRYPTO_BLOCKBYTES (8)

/* 
 * Primitive polynomial modulo reduced by x^128 in GF(2^{128})
 * p(x) = x^128 + x^7 + x^2 + x + 1
 * p(x) mod x^128 = x^7 + x^2 + x + 1
 */ 
#define PRIM_POLY_MOD_128	(0x87)

/**********************************************************************
 * 
 * @name	:	PARTIAL_BLOCK_LEN
 * 
 * @note	:	Computes the number of bytes in the (possibly) partial
 * 				block.
 * 
 **********************************************************************/		
#define PARTIAL_BLOCK_LEN(blks_num,byte_len)	(byte_len-((blks_num-1)*CRYPTO_BLOCKBYTES))

/**********************************************************************
 * 
 * @name	:	PARTIAL_DIBLOCK_LEN
 * 
 * @note	:	Computes the number of bytes in the (possibly) partial
 * 				block.
 * 
 **********************************************************************/		
#define PARTIAL_DIBLOCK_LEN(diblks_num,byte_len)	(byte_len-(2*(diblks_num-1)*CRYPTO_BLOCKBYTES))

typedef unsigned char u8;
typedef unsigned long long u64;

void twegift_enc(u8 *ct, const u8 *key, const u8 *twk, const u8 *pt);

void twegift_dec(u8 *pt, const u8 *key, const u8 *twk, const u8 *ct);

#endif
