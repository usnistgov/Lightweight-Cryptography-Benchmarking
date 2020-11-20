/******************************************************************************
* Constant-time implementation of SKINNY-AEAD-M1 (v1.1).
*
* Two blocks are treated in parallel with SKINNY-128-384 whenever possible.
*
* For more details, see the paper at: https://
*
* @author   Alexandre Adomnicai, Nanyang Technological University,
*           alexandre.adomnicai@ntu.edu.sg
*
* @date     May 2020
******************************************************************************/
#include "skinny128.h"
#include "skinnyaead.h"
#include <string.h>
#include <stdio.h>

/******************************************************************************
* x ^= y where x, y are 128-bit blocks (16 bytes array).
******************************************************************************/
static void xor_block(u8 * x, const u8* y) {
    for(int i = 0; i < BLOCKBYTES; i++)
        x[i] ^= y[i];
}

/******************************************************************************
* Process the associated data. Common to SKINNY-AEAD-M1 encrypt and decrypt
* functions.
******************************************************************************/
static void skinny_aead_m1_auth(u8* auth, u8* c, u8* tag, u32* rtk1,
                    u32* rtk2_3, u64 mlen, const u8* ad, u64 adlen) {
    u64 lfsr = 1;
    u8 feedback;
    u8 tmp[2*BLOCKBYTES];
    memset(tmp, 0x00, 2*BLOCKBYTES);
    memset(auth, 0x00, BLOCKBYTES);
    SET_DOMAIN(tmp, 0x02);
    while (adlen >= 2*BLOCKBYTES) {
        LE_STR_64(tmp, lfsr);
        UPDATE_LFSR(lfsr);
        LE_STR_64(tmp + BLOCKBYTES, lfsr);
        SET_DOMAIN(tmp + BLOCKBYTES, 0x02);
        tkschedule_perm_tk1(rtk1, tmp, tmp+BLOCKBYTES);
        skinny128_384(tmp, tmp+BLOCKBYTES, ad, ad+BLOCKBYTES, rtk1, rtk2_3);
        xor_block(auth, tmp);
        xor_block(auth, tmp + BLOCKBYTES);
        adlen -= 2*BLOCKBYTES;
        ad += 2*BLOCKBYTES;
        UPDATE_LFSR(lfsr);
    }
    if (adlen > BLOCKBYTES) {                       // pad and process 2 blocs
        LE_STR_64(tmp, lfsr);
        UPDATE_LFSR(lfsr);
        LE_STR_64(tmp + BLOCKBYTES, lfsr);
        SET_DOMAIN(tmp + BLOCKBYTES, 0x03);         // domain for padding ad
        tkschedule_perm_tk1(rtk1, tmp, tmp + BLOCKBYTES);
        adlen -= BLOCKBYTES;
        memset(tmp, 0x00, BLOCKBYTES);
        memcpy(tmp, ad + BLOCKBYTES, adlen);
        tmp[adlen] ^= 0x80;                         // padding
        skinny128_384(tmp + BLOCKBYTES, tmp, ad, tmp, rtk1, rtk2_3);
        xor_block(auth, tmp);
        xor_block(auth, tmp + BLOCKBYTES);
    } else if (adlen == BLOCKBYTES) {
        LE_STR_64(tmp, lfsr);
        if (mlen == 0) {                // if tag has *NOT* been calculated yet
            tkschedule_perm_tk1(rtk1, tmp, tag);
            skinny128_384(auth, c, ad, c, rtk1, rtk2_3); 
        } else {                        // if tag has  been calculated yet
            tkschedule_perm_tk1(rtk1, tmp, tmp);    // process last ad block
            skinny128_384(auth, auth, ad, ad, rtk1, rtk2_3);
        }
    } else if (adlen > 0) {
        LE_STR_64(tmp, lfsr);
        SET_DOMAIN(tmp, 0x03);                      // domain for padding ad
        memset(tmp + BLOCKBYTES, 0x00, BLOCKBYTES); // padding
        memcpy(tmp + BLOCKBYTES, ad, adlen);        // padding
        tmp[BLOCKBYTES + adlen] ^= 0x80;            // padding
        if (mlen == 0) {                // if tag has *NOT* been calculated yet
            tkschedule_perm_tk1(rtk1, tmp, tag);    // compute the tag
            skinny128_384(auth, c, tmp + BLOCKBYTES, c, rtk1, rtk2_3); 
        } else {                        // if tag has been calculated yet
            tkschedule_perm_tk1(rtk1, tmp,  tmp);   // process last ad block
            skinny128_384(auth, auth, tmp + BLOCKBYTES, tmp + BLOCKBYTES, rtk1, rtk2_3);
        }
    }
}

/******************************************************************************
* Encryption and authentication using SKINNY-AEAD-M1
******************************************************************************/
int crypto_aead_encrypt (unsigned char *c, unsigned long long *clen,
                    const unsigned char *m, unsigned long long mlen,
                    const unsigned char *ad, unsigned long long adlen,
                    const unsigned char *nsec,
                    const unsigned char *npub,
                    const unsigned char *k) {
    u8 feedback;
    u64 i,lfsr = 1;
    u32 rtk1[8*16];
    u32 rtk2_3[8*SKINNY128_384_ROUNDS];
    u8 tmp[2*BLOCKBYTES], tag[BLOCKBYTES], auth[BLOCKBYTES], sum[BLOCKBYTES];
    (void)nsec;

    // ----------------- Initialization -----------------
    *clen = mlen + TAGBYTES;
    tkschedule_lfsr_2(rtk2_3, npub, npub, SKINNY128_384_ROUNDS);
    tkschedule_lfsr_3(rtk2_3, k, k, SKINNY128_384_ROUNDS);
    tkschedule_perm(rtk2_3);
    memset(tmp, 0x00, 2*BLOCKBYTES);
    memset(tag, 0x00, BLOCKBYTES);
    memset(auth, 0x00, BLOCKBYTES);
    memset(sum, 0x00, BLOCKBYTES);
    // ----------------- Initialization -----------------

    // ----------------- Process the plaintext -----------------
    while (mlen >= 2*BLOCKBYTES) {          // process 2 blocks in //
        LE_STR_64(tmp, lfsr);
        UPDATE_LFSR(lfsr);
        LE_STR_64(tmp + BLOCKBYTES, lfsr);
        tkschedule_perm_tk1(rtk1, tmp, tmp + BLOCKBYTES);
        skinny128_384(c, c + BLOCKBYTES, m, m + BLOCKBYTES, rtk1, rtk2_3);
        xor_block(sum, m);                 // sum for tag computation
        xor_block(sum, m + BLOCKBYTES);    // sum for tag computation
        mlen -= 2*BLOCKBYTES;
        c += 2*BLOCKBYTES;
        m += 2*BLOCKBYTES;
        UPDATE_LFSR(lfsr);
    }
    SET_DOMAIN(tag, 0x04);                  // domain for tag computation
    if (mlen > BLOCKBYTES) {                // pad and process 2 blocs in //
        LE_STR_64(tmp, lfsr);
        UPDATE_LFSR(lfsr);
        LE_STR_64(tmp + BLOCKBYTES, lfsr);
        SET_DOMAIN(tmp + BLOCKBYTES, 0x01); // domain for padding m
        tkschedule_perm_tk1(rtk1, tmp, tmp + BLOCKBYTES);
        skinny128_384(c, auth, m, auth, rtk1, rtk2_3);
        xor_block(sum, m);
        for(i = 0; i < mlen - BLOCKBYTES; i++) {
            c[BLOCKBYTES + i] = auth[i] ^ m[BLOCKBYTES + i];
            sum[i] ^= m[BLOCKBYTES + i]; 
        }
        sum[i] ^= 0x80;                     // padding
        SET_DOMAIN(tag, 0x05);              // domain for tag computation
        m += mlen;
        c += mlen;
        mlen = 0;
        UPDATE_LFSR(lfsr);
    } else if (mlen == BLOCKBYTES) {        // last block is full
        LE_STR_64(tmp, lfsr);
        UPDATE_LFSR(lfsr);
        LE_STR_64(tmp + BLOCKBYTES, lfsr);
        SET_DOMAIN(tmp + BLOCKBYTES, 0x04); // domain for tag computation
        xor_block(sum, m);                  // sum for tag computation
        tkschedule_perm_tk1(rtk1, tmp, tmp + BLOCKBYTES);
        skinny128_384(c, sum, m, sum, rtk1, rtk2_3);
        c += BLOCKBYTES;
    } else if (mlen > 0) {                  // last block is partial
        LE_STR_64(tmp, lfsr);
        SET_DOMAIN(tmp, 0x01);              // domain for padding
        UPDATE_LFSR(lfsr);
        LE_STR_64(tmp + BLOCKBYTES, lfsr);
        SET_DOMAIN(tmp + BLOCKBYTES, 0x05); // domain for tag computation
        for(i = 0; i < mlen; i++)           // sum for tag computation
            sum[i] ^= m[i];                 // sum for tag computation
        sum[i] ^= 0x80;                     // padding
        tkschedule_perm_tk1(rtk1, tmp, tmp + BLOCKBYTES);
        skinny128_384(auth, sum, auth, sum, rtk1, rtk2_3);
        for(i = 0; i < mlen; i++)
            c[i] = auth[i] ^ m[i];          // encrypted padded block
        c += mlen;
    }
    if (mlen == 0) {            // if tag has *NOT* been calculated yet 
        LE_STR_64(tag, lfsr);   // lfsr for tag computation                            
        if((adlen % 32) == 0 || (adlen % 32) > BLOCKBYTES) {
            tkschedule_perm_tk1(rtk1, tag, tag);
            skinny128_384(sum, sum, sum, sum,  rtk1, rtk2_3); // compute the tag
        }
    }
    // ----------------- Process the plaintext -----------------

    // ----------------- Process the associated data -----------------
    skinny_aead_m1_auth(auth, sum, tag, rtk1, rtk2_3, mlen, ad, adlen);
    xor_block(sum, auth);
    memcpy(c, sum, TAGBYTES);
    // ----------------- Process the associated data -----------------

    return 0;
}


/******************************************************************************
* Decryption and authentication using SKINNY-AEAD-M1
******************************************************************************/
int crypto_aead_decrypt (unsigned char *m, unsigned long long *mlen,
                    unsigned char *nsec,
                    const unsigned char *c, unsigned long long clen,
                    const unsigned char *ad, unsigned long long adlen,
                    const unsigned char *npub,
                    const unsigned char *k) {
    u8 feedback;
    u64 i,lfsr = 1;
    u32 rtk1[8*16];
    u32 rtk2_3[8*SKINNY128_384_ROUNDS];
    u8 tmp[2*BLOCKBYTES];
    u8 sum[BLOCKBYTES], tag[BLOCKBYTES], auth[BLOCKBYTES];
    (void)nsec;

    if (clen < TAGBYTES)
        return -1;

    // ----------------- Initialization -----------------
    clen -= TAGBYTES;
    *mlen = clen;
    tkschedule_lfsr_2(rtk2_3, npub, npub, SKINNY128_384_ROUNDS);
    tkschedule_lfsr_3(rtk2_3, k, k, SKINNY128_384_ROUNDS);
    tkschedule_perm(rtk2_3);
    memset(tmp, 0x00, 2*BLOCKBYTES);
    memset(tag, 0x00, BLOCKBYTES);
    memset(auth, 0x00, BLOCKBYTES);
    memset(sum, 0x00, BLOCKBYTES);
    // ----------------- Initialization -----------------

    // ----------------- Process the plaintext -----------------
    while (clen >= 2*BLOCKBYTES) {          // process 2 blocks in //
        LE_STR_64(tmp, lfsr);
        UPDATE_LFSR(lfsr);
        LE_STR_64(tmp + BLOCKBYTES, lfsr);
        tkschedule_perm_tk1(rtk1, tmp, tmp + BLOCKBYTES);
        skinny128_384_inv(m, m + BLOCKBYTES, c, c + BLOCKBYTES, rtk1, rtk2_3);
        xor_block(sum, m);                 // sum for tag computation
        xor_block(sum, m + BLOCKBYTES);    // sum for tag computation
        clen -= 2*BLOCKBYTES;
        c += 2*BLOCKBYTES;
        m += 2*BLOCKBYTES;
        UPDATE_LFSR(lfsr);
    }
    SET_DOMAIN(tag, 0x04);                  // domain for tag computation
    if (clen > BLOCKBYTES) {                // pad and process 2 blocs in //
        LE_STR_64(tmp, lfsr);
        tkschedule_perm_tk1(rtk1, tmp, tmp);
        skinny128_384_inv(m, m, c, c, rtk1, rtk2_3);
        xor_block(sum, m);
        UPDATE_LFSR(lfsr);
        LE_STR_64(tmp, lfsr);
        SET_DOMAIN(tmp, 0x01);              // domain for padding m
        tkschedule_perm_tk1(rtk1, tmp, tmp);
        skinny128_384(auth, auth, auth, auth, rtk1, rtk2_3);
        for(i = 0; i < clen - BLOCKBYTES; i++) {
            m[BLOCKBYTES + i] = auth[i] ^ c[BLOCKBYTES + i];
            sum[i] ^= m[BLOCKBYTES + i]; 
        }
        sum[i] ^= 0x80;                     // padding
        SET_DOMAIN(tag, 0x05);              // domain for tag computation
        c += clen;
        clen = 0;
        UPDATE_LFSR(lfsr);
    } else if (clen == BLOCKBYTES) {        // last block is full
        LE_STR_64(tmp, lfsr);
        tkschedule_perm_tk1(rtk1, tmp, tmp);
        skinny128_384_inv(m, m, c, c, rtk1, rtk2_3);
        xor_block(sum, m);                  // sum for tag computation
        SET_DOMAIN(tag, 0x04);              // domain for tag computation
        UPDATE_LFSR(lfsr);
        c += BLOCKBYTES;
        clen = 0;
    } else if (clen > 0) {                  // last block is partial
        LE_STR_64(tmp, lfsr);
        SET_DOMAIN(tmp, 0x01);              // domain for padding
        tkschedule_perm_tk1(rtk1, tmp, tmp);
        skinny128_384(auth, auth, auth, auth, rtk1, rtk2_3);
        for(i = 0; i < clen; i++) {
            m[i] = auth[i] ^ c[i];          // encrypted padded block
            sum[i] ^= m[i];                 // sum for tag computation
        }
        sum[i] ^= 0x80;                     // padding
        SET_DOMAIN(tag, 0x05);              // domain for tag computation
        UPDATE_LFSR(lfsr);
        c += clen;
        clen = 0;
    }
    if (clen == 0) {                    // if tag has *NOT* been calculated yet
        LE_STR_64(tag, lfsr);
        if((adlen % 32) == 0 || (adlen % 32) > BLOCKBYTES) {
            tkschedule_perm_tk1(rtk1, tag, tag); //if AD can be processed in //
            skinny128_384(sum, sum, sum, sum, rtk1, rtk2_3); // compute the tag
        }
    }

    // ----------------- Process the associated data -----------------
    skinny_aead_m1_auth(auth, sum, tag, rtk1, rtk2_3, clen, ad, adlen);
    xor_block(sum, auth);
    feedback = 0;
    for(i = 0; i < TAGBYTES; i++)
        feedback |= sum[i] ^ c[i];  // constant-time tag verification
    return feedback;
    // ----------------- Process the associated data -----------------
}