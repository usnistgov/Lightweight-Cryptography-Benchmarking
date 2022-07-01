#include "skinny128.h"
#include "romulus.h"
#include <string.h>

//Decryption and tag verification using Romulus-N1
int crypto_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k) {

    u32 tmp;
    skinny_128_384_tks tks;
    u8 state[BLOCKBYTES], pad[BLOCKBYTES];
    (void)nsec;

    if (clen < TAGBYTES)
        return -1;

    // ----------------- Initialization -----------------
    *mlen = clen - TAGBYTES;
    memset(tks.tk1, 0x00, KEYBYTES);
    memset(state, 0x00, BLOCKBYTES);
    tks.tk1[0] = 0x01;                      // Init 56-bit LFSR counter
    // ----------------- Initialization -----------------

    // ----------------- Process the associated data -----------------
    if (adlen == 0) {                       // Handle the special case of no AD
        UPDATE_CTR(tks.tk1);
        SET_DOMAIN(tks, 0x1A);
        tkschedule_lfsr(tks.rtk, npub, k, SKINNY128_384_ROUNDS);
        tkschedule_perm(tks.rtk);
        tkschedule_perm_tk1(tks.rtk1, tks.tk1);
        skinny128_384(state, tks.rtk, state, tks.rtk1);
    } else {                                // Process double blocks except the last
        SET_DOMAIN(tks, 0x08);
        while (adlen > 2*BLOCKBYTES) {
            UPDATE_CTR(tks.tk1);
            XOR_BLOCK(state, state, ad);
            tkschedule_lfsr(tks.rtk, ad + BLOCKBYTES, k, SKINNY128_384_ROUNDS);
            tkschedule_perm(tks.rtk);
            tkschedule_perm_tk1(tks.rtk1, tks.tk1);
            skinny128_384(state, tks.rtk, state, tks.rtk1); 
            UPDATE_CTR(tks.tk1);
            ad += 2*BLOCKBYTES;
            adlen -= 2*BLOCKBYTES;
        }
        // Pad and process the left-over blocks 
        UPDATE_CTR(tks.tk1);
        if (adlen == 2*BLOCKBYTES) {        // Left-over complete double block
            XOR_BLOCK(state, state, ad);
            tkschedule_lfsr(tks.rtk, ad + BLOCKBYTES, k, SKINNY128_384_ROUNDS);
            tkschedule_perm(tks.rtk);
            tkschedule_perm_tk1(tks.rtk1, tks.tk1);
            skinny128_384(state, tks.rtk, state, tks.rtk1); 
            UPDATE_CTR(tks.tk1);
            SET_DOMAIN(tks, 0x18);
        } else if (adlen > BLOCKBYTES) {    // Left-over partial double block
            adlen -= BLOCKBYTES;
            XOR_BLOCK(state, state, ad);
            memcpy(pad, ad + BLOCKBYTES, adlen);
            memset(pad + adlen, 0x00, 15 - adlen);
            pad[15] = adlen;
            tkschedule_lfsr(tks.rtk, pad, k, SKINNY128_384_ROUNDS);
            tkschedule_perm(tks.rtk);
            tkschedule_perm_tk1(tks.rtk1, tks.tk1);
            skinny128_384(state, tks.rtk, state, tks.rtk1); 
            UPDATE_CTR(tks.tk1);
            SET_DOMAIN(tks, 0x1A);
        } else if (adlen == BLOCKBYTES) {   // Left-over complete single block 
            XOR_BLOCK(state, state, ad);
            SET_DOMAIN(tks, 0x18);
        } else {                            // Left-over partial single block
            for(int i = 0; i < (int)adlen; i++)
                state[i] ^= ad[i];
            state[15] ^= adlen;             // Padding
            SET_DOMAIN(tks, 0x1A);
        }
        tkschedule_lfsr(tks.rtk, npub, k, SKINNY128_384_ROUNDS);
        tkschedule_perm(tks.rtk);
        tkschedule_perm_tk1(tks.rtk1, tks.tk1);
        skinny128_384(state, tks.rtk, state, tks.rtk1);
    }
    // ----------------- Process the associated data -----------------

    // ----------------- Process the ciphertext -----------------
    clen -= TAGBYTES;
    memset(tks.tk1, 0x00, KEYBYTES/2);
    tks.tk1[0] = 0x01;                      // Init the 56-bit LFSR counter
    if (clen == 0) {
        UPDATE_CTR(tks.tk1);
        SET_DOMAIN(tks, 0x15);
        tkschedule_perm_tk1(tks.rtk1, tks.tk1);
        skinny128_384(state, tks.rtk, state, tks.rtk1);
    } else {                                // Process all blocks except the last
        SET_DOMAIN(tks, 0x04);
        while (clen > BLOCKBYTES) {
            RHO_INV(state,c,m);
            UPDATE_CTR(tks.tk1);
            tkschedule_perm_tk1(tks.rtk1, tks.tk1);
            skinny128_384(state, tks.rtk, state, tks.rtk1);
            c += BLOCKBYTES;
            m += BLOCKBYTES;
            clen -= BLOCKBYTES;
        }
        // Pad and process the last block
        UPDATE_CTR(tks.tk1);
        if (clen < BLOCKBYTES) {            // Last message double block is partial
            for(int i = 0; i < (int)clen; i++) {
                m[i] = c[i] ^ (state[i] >> 1) ^ (state[i] & 0x80) ^ (state[i] << 7);
                state[i] ^= m[i];
            }
            state[15] ^= (u8)clen;          // Padding
            SET_DOMAIN(tks, 0x15);
        } else {                            // Last message double block is full
            RHO_INV(state,c,m);
            SET_DOMAIN(tks, 0x14);
        }
        tkschedule_perm_tk1(tks.rtk1, tks.tk1);
        skinny128_384(state, tks.rtk, state, tks.rtk1);
    }
    // ----------------- Process the plaintext -----------------

    // ----------------- Generate and check the tag -----------------
    G(state,state);
    tmp = 0;
    for(int i = 0; i < TAGBYTES; i++)
        tmp |= state[i] ^ c[clen+i];        // Constant-time tag comparison
    // ----------------- Generate and check the tag -----------------

    return tmp;
}
