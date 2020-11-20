#ifndef _HYENA_H_
#define _HYENA_H_

#include <string.h>
#include <stdlib.h>

typedef unsigned char u8; 
typedef unsigned int u32;
typedef unsigned long long int u64; 

/* 
 * No. of block cipher rounds to be used
 */ 
#define CRYPTO_BC_NUM_ROUNDS (40)

/*
 * Generate encryption round keys.
 */
#define _GIFT_ENC_ROUND_KEY_GEN(round_keys, key)		(generate_round_keys(round_keys, key))

/*
 * Generate decryption round keys.
 */
#define _GIFT_DEC_ROUND_KEY_GEN(round_keys, key)		(generate_round_keys(round_keys, key))

void generate_round_keys(u8 (*round_key_nibbles)[32], const u8 *key_bytes);

void gift_enc(u8 *ct, const u8 (*round_keys)[32], const u8 *pt);

#endif
