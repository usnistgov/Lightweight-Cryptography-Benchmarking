/******************************************************************************
* Constant-time implementation of SKINNY-AEAD-M1(v1).
*
* For more details, see the paper at: https://
*
* @author   Alexandre Adomnicai, Nanyang Technological University,
*           alexandre.adomnicai@ntu.edu.sg
*
* @date     June 2020
******************************************************************************/
#include "skinnyaead.h"
#include <string.h>

/******************************************************************************
* x ^= y where x, y are 128-bit blocks (16 bytes array).
******************************************************************************/
static void xor_block(u8 * x, const u8* y) {
    for(int i = 0; i < BLOCKBYTES; i++)
        x[i] ^= y[i];
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
    u64 i,lfsr = 1;
    u8 feedback;
    u32 rtk1[4*16];
    u32 rtk2_3[4*SKINNY128_384_ROUNDS];
    u8 tmp[2*BLOCKBYTES], auth[BLOCKBYTES];
    (void)nsec;

    // ----------------- Initialization -----------------
    *clen = mlen + TAGBYTES;
    precompute_rtk2_3(rtk2_3, npub, k);
    memset(tmp, 0x00, 2*BLOCKBYTES);
    memset(auth, 0x00, BLOCKBYTES);
    memset(c + mlen, 0x00, BLOCKBYTES);
    // ----------------- Initialization -----------------

    // ----------------- Process the plaintext -----------------
    while (mlen >= BLOCKBYTES) {        // while entire blocks to process
        LE_STR_64(tmp, lfsr);
        precompute_rtk1(rtk1, tmp);     // precompute RTK1 given the LFSR
        skinny128_384_encrypt(c, m, rtk1, rtk2_3);
        xor_block(c + mlen, m);         // sum for tag computation
        mlen -= BLOCKBYTES;
        c += BLOCKBYTES;
        m += BLOCKBYTES;
        UPDATE_LFSR(lfsr);              // update lfsr for next block
    }
    SET_DOMAIN(tmp, 0x04);              // domain for tag computation
    if (mlen > 0) {                     // last block is partial
        LE_STR_64(tmp, lfsr);           // lfsr for last block
        SET_DOMAIN(tmp, 0x01);          // domain for padding
        for(i = 0; i < mlen; i++)
            c[mlen + i] ^= m[i];        // sum for tag computation
        c[mlen + i] ^= 0x80;            // padding
        precompute_rtk1(rtk1, tmp);
        skinny128_384_encrypt(auth, auth, rtk1, rtk2_3);
        for(i = 0; i < mlen; i++)
            c[i] = auth[i] ^ m[i];      // encrypted padded block
        c += mlen;
        SET_DOMAIN(tmp, 0x05);          // domain for tag computation
        UPDATE_LFSR(lfsr);
    }
    LE_STR_64(tmp, lfsr);               // lfsr for tag computation                                  
    precompute_rtk1(rtk1, tmp);
    skinny128_384_encrypt(c, c, rtk1, rtk2_3); // compute the tag
    // ----------------- Process the plaintext -----------------

    // ----------------- Process the associated data -----------------
    lfsr = 1;
    SET_DOMAIN(tmp, 0x02);
    memset(auth, 0x00, BLOCKBYTES);
    while (adlen >= BLOCKBYTES) {
        LE_STR_64(tmp, lfsr);
        precompute_rtk1(rtk1, tmp);
        skinny128_384_encrypt(tmp + BLOCKBYTES, ad, rtk1, rtk2_3);
        xor_block(auth, tmp + BLOCKBYTES);
        adlen -= BLOCKBYTES;
        ad += BLOCKBYTES;
        UPDATE_LFSR(lfsr);
    }
    if (adlen > 0) {
        LE_STR_64(tmp, lfsr);
        SET_DOMAIN(tmp, 0x03);          // domain for padding ad
        precompute_rtk1(rtk1, tmp);
        memset(tmp, 0x00, BLOCKBYTES);  // padding
        memcpy(tmp, ad, adlen);         // padding
        tmp[adlen] ^= 0x80;             // padding
        skinny128_384_encrypt(tmp, tmp, rtk1, rtk2_3);
        xor_block(auth, tmp);
    }
    xor_block(c, auth);                 // XOR for tag computation
    // ----------------- Process the associated data -----------------
    return 0;
}

/******************************************************************************
* Encryption and authentication using SKINNY-AEAD-M1
******************************************************************************/
int crypto_aead_decrypt (unsigned char *m, unsigned long long *mlen,
                    unsigned char *nsec,
                    const unsigned char *c, unsigned long long clen,
                    const unsigned char *ad, unsigned long long adlen,
                    const unsigned char *npub,
                    const unsigned char *k) {
    u64 i,lfsr = 1;
    u8 feedback;
    u32 rtk1[4*16];
    u32 rtk2_3[4*SKINNY128_384_ROUNDS];
    u8 tmp[2*BLOCKBYTES], auth[BLOCKBYTES], sum[BLOCKBYTES];
    (void)nsec;

    if (clen < TAGBYTES)
        return -1;

    // ----------------- Initialization -----------------
    clen -= TAGBYTES;
    *mlen = clen;
    precompute_rtk2_3(rtk2_3, npub, k);
    memset(tmp, 0x00, 2*BLOCKBYTES);
    memset(auth, 0x00, BLOCKBYTES);
    memset(sum, 0x00, BLOCKBYTES);
    // ----------------- Initialization -----------------

    // ----------------- Process the plaintext -----------------
    while (clen >= BLOCKBYTES) {        // while entire blocks to process
        LE_STR_64(tmp, lfsr);
        precompute_rtk1(rtk1, tmp);     // precompute RTK1 given the LFSR
        skinny128_384_decrypt(m, c, rtk1, rtk2_3);
        xor_block(sum, m);              // sum for tag computation
        clen -= BLOCKBYTES;
        c += BLOCKBYTES;
        m += BLOCKBYTES;
        UPDATE_LFSR(lfsr);              // update LFSR for the next block
    }
    SET_DOMAIN(tmp, 0x04);              // domain for tag computation
    if (clen > 0) {                     // last block is partial
        LE_STR_64(tmp, lfsr);           // lfsr for last block
        SET_DOMAIN(tmp, 0x01);          // domain for padding
        precompute_rtk1(rtk1, tmp);
        skinny128_384_encrypt(auth, auth, rtk1, rtk2_3);
        for(i = 0; i < clen; i++) {
            m[i] = auth[i] ^ c[i];      // encrypted padded block
            sum[i] ^= m[i];             // sum for tag computation
        }
        sum[i] ^= 0x80;                 // padding
        c += clen;
        SET_DOMAIN(tmp, 0x05);          // domain for tag computation
        UPDATE_LFSR(lfsr);
    }
    LE_STR_64(tmp, lfsr);               // lfsr for tag computation                                  
    precompute_rtk1(rtk1, tmp);
    skinny128_384_encrypt(sum, sum, rtk1, rtk2_3); // compute the tag
    // ----------------- Process the plaintext -----------------

    // ----------------- Process the associated data -----------------
    lfsr = 1;
    SET_DOMAIN(tmp, 0x02);
    memset(auth, 0x00, BLOCKBYTES);
    while (adlen >= BLOCKBYTES) {
        LE_STR_64(tmp, lfsr);
        precompute_rtk1(rtk1, tmp);
        skinny128_384_encrypt(tmp + BLOCKBYTES, ad, rtk1, rtk2_3);
        xor_block(auth, tmp + BLOCKBYTES);
        adlen -= BLOCKBYTES;
        ad += BLOCKBYTES;
        UPDATE_LFSR(lfsr);
    }
    if (adlen > 0) {
        LE_STR_64(tmp, lfsr);
        SET_DOMAIN(tmp, 0x03);          // domain for padding ad
        precompute_rtk1(rtk1, tmp);
        memset(tmp, 0x00, BLOCKBYTES);  // padding
        memcpy(tmp, ad, adlen);         // padding
        tmp[adlen] ^= 0x80;             // padding
        skinny128_384_encrypt(tmp, tmp, rtk1, rtk2_3);
        xor_block(auth, tmp);
    }
    xor_block(sum, auth);               // XOR for tag computation
    feedback = 0;
    for(i = 0; i < TAGBYTES; i++)
        feedback |= sum[i] ^ c[i];      // constant-time tag verification
    return feedback;
    // ----------------- Process the associated data -----------------
}
