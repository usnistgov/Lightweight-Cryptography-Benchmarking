/**
 * The ForkSkinny construction.
 * 
 * @file forkskinny.h
 * @author Antoon Purnal <antoon.purnal@esat.kuleuven.be>
 */

#ifndef FORKSKINNY_H
#define FORKSKINNY_H

#include <stdint.h>

#include "api.h"

enum encrypt_selector {
    
    ENC_C0, // "Left" block
    ENC_C1, // "Right" block
    ENC_BOTH // Both blocks

};

enum inversion_selector {
    
    INV_INVERSE, // Plaintext block
    INV_OTHER, // Other ciphertext block
    INV_BOTH // Both blocks

};


#if CRYPTO_BLOCKSIZE == 8
	#define forkEncrypt(C0, C1, input, tweakey, s) forkEncrypt_64(C0, C1, input, tweakey, s)
	#define forkInvert(P, C1, C_j, tweakey, b, s) forkInvert_64(P, C1, C_j, tweakey, b, s)
#else
	#define forkEncrypt(C0, C1, input, tweakey, s) forkEncrypt_128(C0, C1, input, tweakey, s)
	#define forkInvert(P, C1, C_j, tweakey, b, s) forkInvert_128(P, C1, C_j, tweakey, b, s)
#endif


void forkEncrypt_128(unsigned char* C0, unsigned char* C1, unsigned char* input, const unsigned char* userkey, const enum encrypt_selector s);

void forkInvert_128(unsigned char* inverse, unsigned char* C_other, unsigned char* input, const unsigned char* userkey, uint8_t b, const enum inversion_selector s);

void forkEncrypt_64(unsigned char* C0, unsigned char* C1, unsigned char* input, const unsigned char* userkey, const enum encrypt_selector s);

void forkInvert_64(unsigned char* inverse, unsigned char* C_other, unsigned char* input, const unsigned char* userkey, uint8_t b, const enum inversion_selector s);

#endif /* ifndef FORKSKINNY_H */
