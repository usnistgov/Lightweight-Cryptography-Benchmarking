/******************************************************************************
* Constant-time implementation of Romulus-M1(v1).
*
* For more details, see the paper at: https://
*
* @author   Alexandre Adomnicai, Nanyang Technological University,
*           alexandre.adomnicai@ntu.edu.sg
*
* @date     June 2020
******************************************************************************/
#include "romulus.h"
#include <string.h>

static u8 final_ad_domain (unsigned long long adlen, unsigned long long mlen) {
    u8 domain = 0;
    u32 leftover;
    //Determine which domain bits we need based on the length of the ad
    if (adlen == 0) {
        domain ^= 0x02;         // No message, so only 1 block with padding
    } else {
        leftover = (u32)(adlen % (2 * BLOCKBYTES));
        if (leftover == 0) {    // Even or odd ad length?
            domain ^= 0x08;     // Even with a full double block at the end
        } else if (leftover < BLOCKBYTES) {
            domain ^= 0x02;     // Odd with a partial single block at the end
        } else if (leftover > BLOCKBYTES) {
            domain ^= 0x0A;     // Even with a partial double block at the end
        }
    }
    //Determine which domain bits we need based on the length of the message
    if (mlen == 0) {
        domain ^= 0x01;         // No message, so only 1 block with padding
    } else {
        leftover = (unsigned)(mlen % (2 * BLOCKBYTES));
        if (leftover == 0) {    // Even or odd message length?
            domain ^= 0x04;     // Even with a full double block at the end
        } else if (leftover < BLOCKBYTES) {
            domain ^= 0x01;     // Odd with a partial single block at the end
        } else if (leftover > BLOCKBYTES) {
            domain ^= 0x05;     // Even with a partial double block at the end
        }
    }
    return domain;
}

//Encryption and authentication using Romulus-N1
int crypto_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k) {
    u32 tmp;
    u64 tmp_mlen = mlen;
    const u8* m_auth = m;
    u8 final_domain = 0x30;
    skinny_128_384_tks tks;
    u8 state[BLOCKBYTES], pad[BLOCKBYTES];
    (void)nsec;

    // ----------------- Initialization -----------------
    *clen = mlen + TAGBYTES;
    memset(tks.tk1, 0x00, KEYBYTES);
    memset(state, 0x00, BLOCKBYTES);
    tks.tk1[0] = 0x01;                      // Init the 56-bit LFSR counter
    // ----------------- Initialization -----------------

    // ----------------- Process the associated data -----------------
    final_domain ^= final_ad_domain(adlen, mlen);
    SET_DOMAIN(tks, 0x28);
    while (adlen > 2*BLOCKBYTES) {          // Process double blocks but the last
        UPDATE_CTR(tks.tk1);
        XOR_BLOCK(state, state, ad);
        precompute_rtk2_3(tks.rtk2_3, ad + BLOCKBYTES, k);
        precompute_rtk1(tks.rtk1, tks.tk1);
        skinny128_384(state, state, tks.rtk1, tks.rtk2_3); 
        UPDATE_CTR(tks.tk1);
        ad += 2*BLOCKBYTES;
        adlen -= 2*BLOCKBYTES;
    }
    // Pad and process the left-over blocks 
    if (adlen == 2*BLOCKBYTES) {            // Left-over complete double block
        UPDATE_CTR(tks.tk1);
        XOR_BLOCK(state, state, ad);
        precompute_rtk2_3(tks.rtk2_3, ad + BLOCKBYTES, k);
        precompute_rtk1(tks.rtk1, tks.tk1);
        skinny128_384(state, state, tks.rtk1, tks.rtk2_3);
        UPDATE_CTR(tks.tk1);
    } else if (adlen > BLOCKBYTES) {        // Left-over partial double block
        adlen -= BLOCKBYTES;
        UPDATE_CTR(tks.tk1);
        XOR_BLOCK(state, state, ad);
        memcpy(pad, ad + BLOCKBYTES, adlen);
        memset(pad + adlen, 0x00, 15 - adlen);
        pad[15] = adlen;                    // Padding
        precompute_rtk2_3(tks.rtk2_3, pad, k);
        precompute_rtk1(tks.rtk1, tks.tk1);
        skinny128_384(state, state, tks.rtk1, tks.rtk2_3);
        UPDATE_CTR(tks.tk1);
    } else {
        SET_DOMAIN(tks, 0x2C);
        UPDATE_CTR(tks.tk1);
        if (adlen == BLOCKBYTES) {          // Left-over complete single block 
            XOR_BLOCK(state, state, ad);
        } else {                            // Left-over partial single block
            for(int i =0; i < (int)adlen; i++)
                state[i] ^= ad[i];
            state[15] ^= adlen;             // Padding
        }
        if (tmp_mlen >= BLOCKBYTES) {
            precompute_rtk2_3(tks.rtk2_3, m_auth, k);
            precompute_rtk1(tks.rtk1, tks.tk1);
            skinny128_384(state, state, tks.rtk1, tks.rtk2_3);
            if (tmp_mlen > BLOCKBYTES)
                UPDATE_CTR(tks.tk1);
            tmp_mlen -= BLOCKBYTES;
            m_auth += BLOCKBYTES;
        } else {
            memcpy(pad, m_auth, tmp_mlen);
            memset(pad + tmp_mlen, 0x00, BLOCKBYTES - tmp_mlen - 1);
            pad[15] = (u8)tmp_mlen;             // Padding
            precompute_rtk2_3(tks.rtk2_3, pad, k);
            precompute_rtk1(tks.rtk1, tks.tk1);
            skinny128_384(state, state, tks.rtk1, tks.rtk2_3);
            tmp_mlen = 0;
        }
    }
    // Process all message double blocks except the last
    SET_DOMAIN(tks, 0x2C);
    while (tmp_mlen > 32) {
        UPDATE_CTR(tks.tk1);
        XOR_BLOCK(state, state, m_auth);
        precompute_rtk2_3(tks.rtk2_3, m_auth + BLOCKBYTES, k);
        precompute_rtk1(tks.rtk1, tks.tk1);
        skinny128_384(state, state, tks.rtk1, tks.rtk2_3);
        UPDATE_CTR(tks.tk1);
        m_auth += 2 * BLOCKBYTES;
        tmp_mlen -= 2 * BLOCKBYTES;
    }
    // Process the last message double block
    if (tmp_mlen == 2 * BLOCKBYTES) {             // Last message double block is full
        UPDATE_CTR(tks.tk1);
        XOR_BLOCK(state, state, m_auth);
        precompute_rtk2_3(tks.rtk2_3, m_auth + BLOCKBYTES, k);
        precompute_rtk1(tks.rtk1, tks.tk1);
        skinny128_384(state, state, tks.rtk1, tks.rtk2_3);
    } else if (tmp_mlen > BLOCKBYTES) {         // Last message double block is partial
        tmp_mlen -= BLOCKBYTES;
        UPDATE_CTR(tks.tk1);
        XOR_BLOCK(state, state, m_auth);
        memcpy(pad, m_auth + BLOCKBYTES, tmp_mlen);
        memset(pad + tmp_mlen, 0x00, BLOCKBYTES - tmp_mlen - 1);
        pad[15] = (u8)tmp_mlen;                 // Padding
        precompute_rtk2_3(tks.rtk2_3, pad, k);
        precompute_rtk1(tks.rtk1, tks.tk1);
        skinny128_384(state, state, tks.rtk1, tks.rtk2_3);
    } else if (tmp_mlen == BLOCKBYTES) {        // Last message single block is full
        XOR_BLOCK(state, state, m_auth);
    } else if (tmp_mlen > 0) {                  // Last message single block is partial
        for(int i =0; i < (int)tmp_mlen; i++)
            state[i] ^= m_auth[i];
        state[15] ^= (u8)tmp_mlen;              // Padding
    }
    // Process the last partial block
    SET_DOMAIN(tks, final_domain);
    UPDATE_CTR(tks.tk1);
    precompute_rtk2_3(tks.rtk2_3, npub, k);
    precompute_rtk1(tks.rtk1, tks.tk1);
    skinny128_384(state, state, tks.rtk1, tks.rtk2_3); 
    // ----------------- Process the associated data -----------------

    // ----------------- Generate the tag -----------------
    G(state,state);
    memcpy(c + mlen, state, TAGBYTES);
    // ----------------- Generate the tag -----------------
    memset(tks.tk1, 0x00, KEYBYTES);
    tks.tk1[0] = 0x01;                      // Init the 56-bit LFSR counter
    if (mlen > 0) {
        SET_DOMAIN(tks, 0x24);
        while (mlen > BLOCKBYTES) {
            precompute_rtk1(tks.rtk1, tks.tk1);
            skinny128_384(state, state, tks.rtk1, tks.rtk2_3);
            RHO(state,c,m);
            UPDATE_CTR(tks.tk1);
            c += BLOCKBYTES;
            m += BLOCKBYTES;
            mlen -= BLOCKBYTES;
        }
        precompute_rtk1(tks.rtk1, tks.tk1);
        skinny128_384(state, state, tks.rtk1, tks.rtk2_3);
        for(int i = 0; i < (int)mlen; i++) {
            tmp = m[i];                     // Use of tmp variable in case c = m
            c[i] = m[i] ^ (state[i] >> 1) ^ (state[i] & 0x80) ^ (state[i] << 7);
            state[i] ^= (u8)tmp;
        }
        state[15] ^= (u8)mlen;              // Padding
    }

    return 0;
}

//Decryption and tag verification using Romulus-N1
int crypto_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k) {
    u32 tmp;
    u64 tmp_mlen;
    u8 final_domain = 0x30;
    u8* m_auth = m;
    const u8* c_tmp = c;
    skinny_128_384_tks tks;
    u8 state[BLOCKBYTES], pad[BLOCKBYTES];
    (void)nsec;

    if (clen < TAGBYTES)
        return -1;

    // ----------------- Initialization -----------------
    *mlen = clen - TAGBYTES;
    memset(tks.tk1, 0x00, KEYBYTES);
    tks.tk1[0] = 0x01;                          // Init the 56-bit LFSR counter
    // ----------------- Initialization -----------------

    // ----------------- Process the ciphertext -----------------
    clen -= TAGBYTES;
    memcpy(state, c + clen, TAGBYTES);
    tmp_mlen = clen;
    if (tmp_mlen > 0) {
        SET_DOMAIN(tks, 0x24);
        precompute_rtk2_3(tks.rtk2_3, npub, k);
        while (tmp_mlen > BLOCKBYTES) {
            precompute_rtk1(tks.rtk1, tks.tk1);
            skinny128_384(state, state, tks.rtk1, tks.rtk2_3);
            RHO_INV(state, c, m);
            UPDATE_CTR(tks.tk1);
            c += BLOCKBYTES;
            m += BLOCKBYTES;
            tmp_mlen -= BLOCKBYTES;
        }
        precompute_rtk1(tks.rtk1, tks.tk1);
        skinny128_384(state, state, tks.rtk1, tks.rtk2_3);
        for(int i = 0; i < (int)tmp_mlen; i++) {
            m[i] = c[i] ^ (state[i] >> 1) ^ (state[i] & 0x80) ^ (state[i] << 7);
            state[i] ^= m[i];
        }
        state[15] ^= (u8)tmp_mlen;          // Padding
    }
    // ----------------- Process the ciphertext -----------------
    
    // ----------------- Process the associated data -----------------
    memset(tks.tk1, 0x00, KEYBYTES);
    tks.tk1[0] = 0x01;                      // Init the 56-bit LFSR counter
    memset(state, 0x00, BLOCKBYTES);
    final_domain ^= final_ad_domain(adlen, clen);
    SET_DOMAIN(tks, 0x28);
    while (adlen > 2*BLOCKBYTES) {          // Process double blocks but the last
        UPDATE_CTR(tks.tk1);
        XOR_BLOCK(state, state, ad);
        precompute_rtk2_3(tks.rtk2_3, ad + BLOCKBYTES, k);
        precompute_rtk1(tks.rtk1, tks.tk1);
        skinny128_384(state, state, tks.rtk1, tks.rtk2_3);
        UPDATE_CTR(tks.tk1);
        ad += 2*BLOCKBYTES;
        adlen -= 2*BLOCKBYTES;
    }
    // Pad and process the left-over blocks 
    if (adlen == 2*BLOCKBYTES) {            // Left-over complete double block
        UPDATE_CTR(tks.tk1);
        XOR_BLOCK(state, state, ad);
        precompute_rtk2_3(tks.rtk2_3, ad + BLOCKBYTES, k);
        precompute_rtk1(tks.rtk1, tks.tk1);
        skinny128_384(state, state, tks.rtk1, tks.rtk2_3);
        UPDATE_CTR(tks.tk1);
    } else if (adlen > BLOCKBYTES) {        // Left-over partial double block
        adlen -= BLOCKBYTES;
        UPDATE_CTR(tks.tk1);
        XOR_BLOCK(state, state, ad);
        memcpy(pad, ad + BLOCKBYTES, adlen);
        memset(pad + adlen, 0x00, 15 - adlen);
        pad[15] = adlen;                    // Padding
        precompute_rtk2_3(tks.rtk2_3, pad, k);
        precompute_rtk1(tks.rtk1, tks.tk1);
        skinny128_384(state, state, tks.rtk1, tks.rtk2_3);
        UPDATE_CTR(tks.tk1);
    } else {
        SET_DOMAIN(tks, 0x2C);
        UPDATE_CTR(tks.tk1);
        if (adlen == BLOCKBYTES) {          // Left-over complete single block 
            XOR_BLOCK(state, state, ad);
        } else {                            // Left-over partial single block
            for(int i =0; i < (int)adlen; i++)
                state[i] ^= ad[i];
            state[15] ^= adlen;             // Padding
        }
        if (clen >= BLOCKBYTES) {
            precompute_rtk2_3(tks.rtk2_3, m_auth, k);
            precompute_rtk1(tks.rtk1, tks.tk1);
            skinny128_384(state, state, tks.rtk1, tks.rtk2_3);
            if (clen > BLOCKBYTES)
                UPDATE_CTR(tks.tk1);
            m_auth += BLOCKBYTES;
            clen -= BLOCKBYTES;
        } else {
            memcpy(pad, m_auth, clen);
            memset(pad + clen, 0x00, BLOCKBYTES - clen - 1);
            pad[15] = (u8)clen;             // Padding
            precompute_rtk2_3(tks.rtk2_3, pad, k);
            precompute_rtk1(tks.rtk1, tks.tk1);
            skinny128_384(state, state, tks.rtk1, tks.rtk2_3);
            clen = 0;
        }
    }
    // Process all message double blocks except the last
    SET_DOMAIN(tks, 0x2C);
    while (clen > 32) {
        UPDATE_CTR(tks.tk1);
        XOR_BLOCK(state, state, m_auth);
        precompute_rtk2_3(tks.rtk2_3, m_auth + BLOCKBYTES, k);
        precompute_rtk1(tks.rtk1, tks.tk1);
        skinny128_384(state, state, tks.rtk1, tks.rtk2_3);
        UPDATE_CTR(tks.tk1);
        m_auth += 2 * BLOCKBYTES;
        clen -= 2 * BLOCKBYTES;
    }
    // Process the last message double block
    if (clen == 2 * BLOCKBYTES) {             // Last message double block is full
        UPDATE_CTR(tks.tk1);
        XOR_BLOCK(state, state, m_auth);
        precompute_rtk2_3(tks.rtk2_3, m_auth + BLOCKBYTES, k);
        precompute_rtk1(tks.rtk1, tks.tk1);
        skinny128_384(state, state, tks.rtk1, tks.rtk2_3);
    } else if (clen > BLOCKBYTES) {         // Last message double block is partial
        clen -= BLOCKBYTES;
        UPDATE_CTR(tks.tk1);
        XOR_BLOCK(state, state, m_auth);
        memcpy(pad, m_auth + BLOCKBYTES, clen);
        memset(pad + clen, 0x00, BLOCKBYTES - clen - 1);
        pad[15] = (u8)clen;                 // Padding
        precompute_rtk2_3(tks.rtk2_3, pad, k);
        precompute_rtk1(tks.rtk1, tks.tk1);
        skinny128_384(state, state, tks.rtk1, tks.rtk2_3);
    } else if (clen == BLOCKBYTES) {        // Last message single block is full
        XOR_BLOCK(state, state, m_auth);
    } else if (clen > 0) {                  // Last message single block is partial
        for(int i =0; i < (int)clen; i++)
            state[i] ^= m[i];
        state[15] ^= (u8)clen;              // Padding
    }
    // Process the last partial block
    SET_DOMAIN(tks, final_domain);
    UPDATE_CTR(tks.tk1);
    precompute_rtk2_3(tks.rtk2_3, npub, k);
    precompute_rtk1(tks.rtk1, tks.tk1);
    skinny128_384(state, state, tks.rtk1, tks.rtk2_3);
    // ----------------- Process the associated data -----------------

    // ----------------- Generate and check the tag -----------------
    G(state,state);
    tmp = 0;
    for(int i = 0; i < TAGBYTES; i++)
        tmp |= state[i] ^ c_tmp[*mlen+i];   //constant-time tag comparison
    // ----------------- Generate and check the tag -----------------
    return tmp;
}
