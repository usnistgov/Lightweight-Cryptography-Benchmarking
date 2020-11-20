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
* Process the associated data. Common to SKINNY-AEAD-M1 encrypt and decrypt
* functions.
******************************************************************************/
static void skinny_aead_m1_auth(u8* auth, u8* c, u8* tag, tweakey* tk,
                    u64 mlen, const u8* ad, u64 adlen) {
    u64 lfsr = 1;
    u8 feedback;
    u8 tmp[2*BLOCKBYTES];
    memset(tmp, 0x00, 2*BLOCKBYTES);
    SET_DOMAIN(tmp, 0x02);
    SET_DOMAIN(tmp + BLOCKBYTES, 0x02);
    memset(auth, 0x00, BLOCKBYTES);
    while (adlen >= 2*BLOCKBYTES) {
        LE_STR_64(tmp, lfsr);
        UPDATE_LFSR(lfsr);
        LE_STR_64(tmp + BLOCKBYTES, lfsr);
        precompute_rtk1(tk->rtk1, tmp, tmp+BLOCKBYTES);
        skinny128_384_encrypt(tmp, tmp+BLOCKBYTES, ad, ad+BLOCKBYTES, *tk);
        xor_block(auth, tmp);
        xor_block(auth, tmp + BLOCKBYTES);
        adlen -= 2*BLOCKBYTES;
        ad += 2*BLOCKBYTES;
        UPDATE_LFSR(lfsr);
        memset(tmp, 0x00, 2*BLOCKBYTES);    // to save 32 bytes of RAM
        SET_DOMAIN(tmp, 0x02);
        SET_DOMAIN(tmp + BLOCKBYTES, 0x02);
    }
    if (adlen > BLOCKBYTES) {               // pad and process 2 blocs in //
        LE_STR_64(tmp, lfsr);
        UPDATE_LFSR(lfsr);
        LE_STR_64(tmp + BLOCKBYTES, lfsr);
        SET_DOMAIN(tmp + BLOCKBYTES, 0x03); // domain for padding ad
        precompute_rtk1(tk->rtk1, tmp, tmp + BLOCKBYTES);
        adlen -= BLOCKBYTES;
        memset(tmp, 0x00, BLOCKBYTES);
        memcpy(tmp, ad + BLOCKBYTES, adlen);
        tmp[adlen] ^= 0x80;                 // padding
        skinny128_384_encrypt(tmp + BLOCKBYTES, tmp, ad, tmp, *tk);
        xor_block(auth, tmp);
        xor_block(auth, tmp + BLOCKBYTES);
    } else if (adlen == BLOCKBYTES) {
        LE_STR_64(tmp, lfsr);
        if (mlen == 0) {    // if tag has *NOT* been calculated yet
            precompute_rtk1(tk->rtk1, tmp, tag);    // compute the tag
            skinny128_384_encrypt(tmp, c, ad, c, *tk); 
        } else {            // if tag has  been calculated yet
            precompute_rtk1(tk->rtk1, tmp, tmp);    // process last ad block
            skinny128_384_encrypt(tmp, tmp, ad, ad, *tk);
        }
        xor_block(auth, tmp);
    } else if (adlen > 0) {
        LE_STR_64(tmp, lfsr);
        SET_DOMAIN(tmp, 0x03);                      // domain for padding ad
        memset(tmp + BLOCKBYTES, 0x00, BLOCKBYTES); // padding
        memcpy(tmp + BLOCKBYTES, ad, adlen);        // padding
        tmp[BLOCKBYTES + adlen] ^= 0x80;            // padding
        if (mlen == 0) {    // if tag has *NOT* been calculated yet
            precompute_rtk1(tk->rtk1, tmp, tag);    // compute the tag
            skinny128_384_encrypt(tmp, c, tmp + BLOCKBYTES, c, *tk); 
        } else {            // if tag has been calculated yet
            precompute_rtk1(tk->rtk1, tmp,  tmp);   // process last ad block
            skinny128_384_encrypt(tmp, tmp, tmp + BLOCKBYTES, tmp + BLOCKBYTES, *tk);
        }
        xor_block(auth, tmp);
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
    u64 i,lfsr = 1;
    u8 feedback;
    tweakey tk;
    u8 tmp[2*BLOCKBYTES], tag[BLOCKBYTES], auth[BLOCKBYTES];
    (void)nsec;

    // ----------------- Initialization -----------------
    *clen = mlen + TAGBYTES;
    precompute_rtk2_3(tk.rtk2_3, npub, k, SKINNY128_384_ROUNDS);
    memset(tmp, 0x00, 2*BLOCKBYTES);
    memset(tag, 0x00, BLOCKBYTES);
    memset(auth, 0x00, BLOCKBYTES);
    memset(c + mlen, 0x00, BLOCKBYTES);
    // ----------------- Initialization -----------------

    // ----------------- Process the plaintext -----------------
    while (mlen >= 2*BLOCKBYTES) {          // process 2 blocks in //
        LE_STR_64(tmp, lfsr);               // lfsr for 1st block
        UPDATE_LFSR(lfsr);
        LE_STR_64(tmp + BLOCKBYTES, lfsr);  // lfsr for 2nd block
        precompute_rtk1(tk.rtk1, tmp, tmp + BLOCKBYTES);
        skinny128_384_encrypt(c, c + BLOCKBYTES, m, m + BLOCKBYTES, tk);
        xor_block(c + mlen, m);                 // sum for tag computation
        xor_block(c + mlen, m + BLOCKBYTES);    // sum for tag computation
        mlen -= 2*BLOCKBYTES;
        c += 2*BLOCKBYTES;
        m += 2*BLOCKBYTES;
        UPDATE_LFSR(lfsr);
    }
    SET_DOMAIN(tag, 0x04);                  // domain for tag computation
    if (mlen > BLOCKBYTES) {                // pad and process 2 blocs in //
        LE_STR_64(tmp, lfsr);               // lfsr for 1st block
        UPDATE_LFSR(lfsr);
        LE_STR_64(tmp + BLOCKBYTES, lfsr);  // lfsr for 2nd block
        SET_DOMAIN(tmp + BLOCKBYTES, 0x01);       // domain for padding m
        precompute_rtk1(tk.rtk1, tmp, tmp + BLOCKBYTES);
        skinny128_384_encrypt(c, auth, m, auth, tk);
        xor_block(c + mlen, m);
        for(i = 0; i < mlen - BLOCKBYTES; i++) {
            c[BLOCKBYTES + i] = auth[i] ^ m[BLOCKBYTES + i];
            c[mlen + i] ^= m[BLOCKBYTES + i]; 
        }
        c[mlen + i] ^= 0x80;                    // padding
        SET_DOMAIN(tag, 0x05);                  // domain for tag computation
        m += mlen;
        c += mlen;
        mlen = 0;
        UPDATE_LFSR(lfsr);
    } else if (mlen == BLOCKBYTES) {            // last block is full
        LE_STR_64(tmp, lfsr);                   // lfsr for last full block
        UPDATE_LFSR(lfsr);
        LE_STR_64(tmp + BLOCKBYTES, lfsr);      // lfsr for tag computation
        SET_DOMAIN(tmp + BLOCKBYTES, 0x04);     // domain for tag computation
        xor_block(c + mlen, m);                 // sum for tag computation
        precompute_rtk1(tk.rtk1, tmp, tmp + BLOCKBYTES);
        skinny128_384_encrypt(c, c + mlen, m, c + mlen, tk);
        c += BLOCKBYTES;
    } else if (mlen > 0) {                      // last block is partial
        LE_STR_64(tmp, lfsr);               // lfsr for last block
        SET_DOMAIN(tmp, 0x01);              // domain for padding
        UPDATE_LFSR(lfsr);
        LE_STR_64(tmp + BLOCKBYTES, lfsr);       // lfsr for tag computation
        SET_DOMAIN(tmp + BLOCKBYTES, 0x05);      // domain for tag computation
        for(i = 0; i < mlen; i++)  // sum for tag computation
            c[mlen + i] ^= m[i];                // sum for tag computation
        c[mlen + i] ^= 0x80;                    // padding
        precompute_rtk1(tk.rtk1, tmp, tmp + BLOCKBYTES);
        skinny128_384_encrypt(auth, c + mlen, auth, c + mlen, tk);
        for(i = 0; i < mlen; i++)
            c[i] = auth[i] ^ m[i];               // encrypted padded block
        c += mlen;
    }
    if (mlen == 0) {    // if tag has *NOT* been calculated yet 
        LE_STR_64(tag, lfsr);               // lfsr for tag computation                                     
        if((adlen % 32) == 0 || (adlen % 32) > BLOCKBYTES) {    //if all AD can be processed in //
            precompute_rtk1(tk.rtk1, tag, tag);
            skinny128_384_encrypt(c, c, c, c, tk); // compute the tag
        }
    }
    // ----------------- Process the plaintext -----------------

    // ----------------- Process the associated data -----------------
    skinny_aead_m1_auth(auth, c, tag, &tk, mlen, ad, adlen);
    xor_block(c, auth);
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
    u64 i,lfsr = 1;
    u8 feedback;
    tweakey tk;
    u8 tmp[2*BLOCKBYTES];
    u8 sum[BLOCKBYTES], tag[BLOCKBYTES], auth[BLOCKBYTES];
    (void)nsec;

    if (clen < TAGBYTES)
        return -1;

    // ----------------- Initialization -----------------
    clen -= TAGBYTES;
    *mlen = clen;
    precompute_rtk2_3(tk.rtk2_3, npub, k, SKINNY128_384_ROUNDS);
    memset(tmp, 0x00, 2*BLOCKBYTES);
    memset(tag, 0x00, BLOCKBYTES);
    memset(auth, 0x00, BLOCKBYTES);
    memset(sum, 0x00, BLOCKBYTES);
    // ----------------- Initialization -----------------

    // ----------------- Process the plaintext -----------------
    while (clen >= 2*BLOCKBYTES) {          // process 2 blocks in //
        LE_STR_64(tmp, lfsr);               // lfsr for 1st block
        UPDATE_LFSR(lfsr);
        LE_STR_64(tmp + BLOCKBYTES, lfsr);  // lfsr for 2nd block
        precompute_rtk1(tk.rtk1, tmp, tmp + BLOCKBYTES);
        skinny128_384_decrypt(m, m + BLOCKBYTES, c, c + BLOCKBYTES, tk);
        xor_block(sum, m);                 // sum for tag computation
        xor_block(sum, m + BLOCKBYTES);    // sum for tag computation
        clen -= 2*BLOCKBYTES;
        c += 2*BLOCKBYTES;
        m += 2*BLOCKBYTES;
        UPDATE_LFSR(lfsr);
    }
    SET_DOMAIN(tag, 0x04);                  // domain for tag computation
    if (clen > BLOCKBYTES) {                // pad and process 2 blocs in //
        LE_STR_64(tmp, lfsr);               // lfsr for 1st block
        precompute_rtk1(tk.rtk1, tmp, tmp);
        skinny128_384_decrypt(m, m, c, c, tk);
        xor_block(sum, m);
        UPDATE_LFSR(lfsr);
        LE_STR_64(tmp, lfsr);               // lfsr for 2nd block
        SET_DOMAIN(tmp, 0x01);              // domain for padding m
        precompute_rtk1(tk.rtk1, tmp, tmp);
        skinny128_384_encrypt(auth, auth, auth, auth, tk);
        for(i = 0; i < clen - BLOCKBYTES; i++) {
            m[BLOCKBYTES + i] = auth[i] ^ c[BLOCKBYTES + i];
            sum[i] ^= m[BLOCKBYTES + i]; 
        }
        sum[i] ^= 0x80;                     // padding
        SET_DOMAIN(tag, 0x05);              // domain for tag computation
        m += clen;
        c += clen;
        clen = 0;
        UPDATE_LFSR(lfsr);
    } else if (clen == BLOCKBYTES) {        // last block is full
        LE_STR_64(tmp, lfsr);               // lfsr for last full block
        precompute_rtk1(tk.rtk1, tmp, tmp);
        skinny128_384_decrypt(m, m, c, c, tk);
        xor_block(sum, m);                  // sum for tag computation
        SET_DOMAIN(tag, 0x04);              // domain for tag computation
        UPDATE_LFSR(lfsr);
        c += BLOCKBYTES;
        clen = 0;
    } else if (clen > 0) {                  // last block is partial
        LE_STR_64(tmp, lfsr);               // lfsr for last block
        SET_DOMAIN(tmp, 0x01);              // domain for padding
        precompute_rtk1(tk.rtk1, tmp, tmp);
        skinny128_384_encrypt(auth, auth, auth, auth, tk);
        for(i = 0; i < clen; i++) {
            m[i] = auth[i] ^ c[i];          // encrypted padded block
            sum[i] ^= m[i];                 // sum for tag computation
        }
        sum[i] ^= 0x80;                     // padding
        SET_DOMAIN(tag, 0x05);              // domain for tag computation
        UPDATE_LFSR(lfsr);
        m += clen;
        c += clen;
        clen = 0;
    }
    if (clen == 0) {                // if tag has *NOT* been calculated yet
        LE_STR_64(tag, lfsr);       // lfsr for tag computation                        
        if((adlen % 32) == 0 || (adlen % 32) > BLOCKBYTES) {
            precompute_rtk1(tk.rtk1, tag, tag); //if AD can be processed in //
            skinny128_384_encrypt(sum, sum, sum, sum, tk); // compute the tag
        }
    }

    // ----------------- Process the associated data -----------------
    skinny_aead_m1_auth(auth, sum, tag, &tk, clen, ad, adlen);
    xor_block(sum, auth);
    feedback = 0;
    for(i = 0; i < TAGBYTES; i++)
        feedback |= sum[i] ^ c[i];  // constant-time tag verification
    return feedback;
    // ----------------- Process the associated data -----------------
}
