#include "skinny128.h"
#include "tk_schedule.h"
#include "romulus.h"
#include <string.h>
#include <stdio.h>

//Decryption and tag verification using Romulus-N1
int crypto_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k) {

    int i;
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
    tks.tk1[0] = 0x01;                          //56-bit LFSR counter
    // ----------------- Initialization -----------------

    // ----------------- Process the associated data -----------------
    //Handle the special case of no associated data
    if (adlen == 0) {
        UPDATE_CTR(tks.tk1);
        SET_DOMAIN(tks, 0x1A);
        precompute_rtk2_3(tks.rtk2_3, npub, k);
        precompute_rtk1(tks.rtk1, tks.tk1);
        skinny128_384_plus(state, state, tks.rtk1, tks.rtk2_3);
    } else {
        // Process all double blocks except the last
        SET_DOMAIN(tks, 0x08);
        while (adlen > 2*BLOCKBYTES) {
            UPDATE_CTR(tks.tk1);
            XOR_BLOCK(state, state, ad);
            precompute_rtk2_3(tks.rtk2_3, ad + BLOCKBYTES, k);
            precompute_rtk1(tks.rtk1, tks.tk1);
            skinny128_384_plus(state, state, tks.rtk1, tks.rtk2_3); 
            UPDATE_CTR(tks.tk1);
            ad += 2*BLOCKBYTES;
            adlen -= 2*BLOCKBYTES;
        }
        //Pad and process the left-over blocks 
        UPDATE_CTR(tks.tk1);
        if (adlen == 2*BLOCKBYTES) {
            // Left-over complete double block
            XOR_BLOCK(state, state, ad);
            precompute_rtk2_3(tks.rtk2_3, ad + BLOCKBYTES, k);
            precompute_rtk1(tks.rtk1, tks.tk1);
            skinny128_384_plus(state, state, tks.rtk1, tks.rtk2_3); 
            UPDATE_CTR(tks.tk1);
            SET_DOMAIN(tks, 0x18);
        } else if (adlen > BLOCKBYTES) {
            //  Left-over partial double block
            adlen -= BLOCKBYTES;
            XOR_BLOCK(state, state, ad);
            memcpy(pad, ad + BLOCKBYTES, adlen);
            memset(pad + adlen, 0x00, 15 - adlen);
            pad[15] = adlen;
            precompute_rtk2_3(tks.rtk2_3, pad, k);
            precompute_rtk1(tks.rtk1, tks.tk1);
            skinny128_384_plus(state, state, tks.rtk1, tks.rtk2_3);  
            UPDATE_CTR(tks.tk1);
            SET_DOMAIN(tks, 0x1A);
        } else if (adlen == BLOCKBYTES) {
            //  Left-over complete single block 
            XOR_BLOCK(state, state, ad);
            SET_DOMAIN(tks, 0x18);
        } else {
            // Left-over partial single block
            for(i =0; i < (int)adlen; i++)
                state[i] ^= ad[i];
            state[15] ^= adlen;
            SET_DOMAIN(tks, 0x1A);
        }
        precompute_rtk2_3(tks.rtk2_3, npub, k);
        precompute_rtk1(tks.rtk1, tks.tk1);
        skinny128_384_plus(state, state, tks.rtk1, tks.rtk2_3);
    }
    // ----------------- Process the associated data -----------------

    // ----------------- Process the ciphertext -----------------
    clen -= TAGBYTES;
    memset(tks.tk1, 0, KEYBYTES);
    tks.tk1[0] = 0x01;          //init the 56-bit LFSR counter
    if (clen == 0) {
        UPDATE_CTR(tks.tk1);
        SET_DOMAIN(tks, 0x15);
        precompute_rtk1(tks.rtk1, tks.tk1);
        skinny128_384_plus(state, state, tks.rtk1, tks.rtk2_3);
    } else {
        //process all blocks except the last
        SET_DOMAIN(tks, 0x04);
        while (clen > BLOCKBYTES) {
            RHO_INV(state,c,m);
            UPDATE_CTR(tks.tk1);
            precompute_rtk1(tks.rtk1, tks.tk1);
            skinny128_384_plus(state, state, tks.rtk1, tks.rtk2_3);
            c += BLOCKBYTES;
            m += BLOCKBYTES;
            clen -= BLOCKBYTES;
        }
        //pad and process the last block
        UPDATE_CTR(tks.tk1);
        if (clen < BLOCKBYTES) {
            for(i = 0; i < (int)clen; i++) {
                m[i] = c[i] ^ (state[i] >> 1) ^ (state[i] & 0x80) ^ (state[i] << 7);
                state[i] ^= m[i];
            }
            state[15] ^= (u8)clen; //padding
            SET_DOMAIN(tks, 0x15);
        } else {
            RHO_INV(state,c,m);
            SET_DOMAIN(tks, 0x14);
        }
        precompute_rtk1(tks.rtk1, tks.tk1);
        skinny128_384_plus(state, state, tks.rtk1, tks.rtk2_3);
    }
    // ----------------- Process the plaintext -----------------

    // ----------------- Generate and check the tag -----------------
    G(state,state);
    tmp = 0;
    for(i = 0; i < TAGBYTES; i++)
        tmp |= state[i] ^ c[clen+i];   //constant-time tag comparison
    // ----------------- Generate and check the tag -----------------

    return tmp;
}
