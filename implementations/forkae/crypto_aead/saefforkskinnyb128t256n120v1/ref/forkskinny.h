/**
 * The ForkSkinny construction.
 * 
 * @file forkskinny.h
 * @author Antoon Purnal <antoon.purnal@esat.kuleuven.be>
 */

#ifndef FORKSKINNY_H
#define FORKSKINNY_H

#include <stdint.h>

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

void forkEncrypt(unsigned char* C0, unsigned char* C1, unsigned char* input, const unsigned char* userkey, const enum encrypt_selector s);
void forkInvert(unsigned char* inverse, unsigned char* C_other, unsigned char* input, const unsigned char* userkey, uint8_t b, const enum inversion_selector s);

#endif /* ifndef FORKSKINNY_H */
