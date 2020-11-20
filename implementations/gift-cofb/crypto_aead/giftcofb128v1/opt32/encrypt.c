/*******************************************************************************
* Constant-time 32-bit implementation of the GIFT-COFB authenticated cipher.
* 
* @author   Alexandre Adomnicai, Nanyang Technological University,
*           alexandre.adomnicai@ntu.edu.sg
* @date     January 2020
*******************************************************************************/
#include <string.h> //for memcpy
#include "api.h"
#include "cofb.h"
#include "giftb128.h"

#define TAGBYTES        CRYPTO_ABYTES
#define BLOCKBYTES      CRYPTO_ABYTES
#define COFB_ENCRYPT    1
#define COFB_DECRYPT    0

/****************************************************************************
* 32-bit padding implementation.
****************************************************************************/
static inline void padding(u32* d, const u32* s, const u32 no_of_bytes){
    u32 i;
    if (no_of_bytes == 0) {
        d[0] = 0x00000080; // little-endian
        d[1] = 0x00000000;
        d[2] = 0x00000000;
        d[3] = 0x00000000;
    }
    else if (no_of_bytes < BLOCKBYTES) {
        for (i = 0; i < no_of_bytes/4+1; i++)
            d[i] = s[i];
        d[i-1] &= ~(0xffffffffL << (no_of_bytes % 4)*8);
        d[i-1] |= 0x00000080L << (no_of_bytes % 4)*8;
        for (; i < 4; i++)
            d[i] = 0x00000000;
    }
    else {
        d[0] = s[0];
        d[1] = s[1];
        d[2] = s[2];
        d[3] = s[3];
    }
}

/****************************************************************************
* Constant-time implementation of the GIFT-COFB authenticated cipher based on
* fixsliced GIFTb-128. Encryption/decryption is handled by the same function,
* depending on the 'encrypting' parameter (1/0).
****************************************************************************/
int giftcofb_crypt(u8* out, const u8* key, const u8* nonce, const u8* ad,
                u32 ad_len, const u8* in, u32 in_len, const int encrypting) {

    u32 tmp0, tmp1, emptyA, emptyM;
    u32 offset[2], input[4], rkey[80];
    u8 Y[16];

    if (!encrypting) {
        if (in_len < TAGBYTES)
            return -1;
        in_len -= TAGBYTES;
    }

    if (ad_len == 0)
        emptyA = 1;
    else
        emptyA = 0;

    if (in_len == 0)
        emptyM =1;
    else
        emptyM = 0;

    precompute_rkeys(rkey, key);
    giftb128(Y, nonce, rkey);
    offset[0] = ((u32*)Y)[0];
    offset[1] = ((u32*)Y)[1];

    while (ad_len > BLOCKBYTES) {
        RHO1(input, (u32*)Y, (u32*)ad, BLOCKBYTES);
        DOUBLE_HALF_BLOCK(offset);
        XOR_TOP_BAR_BLOCK(input, offset);
        giftb128(Y, (u8*)input, rkey);
        ad += BLOCKBYTES;
        ad_len -= BLOCKBYTES;
    }
    
    TRIPLE_HALF_BLOCK(offset);
    if ((ad_len % BLOCKBYTES != 0) || (emptyA))
        TRIPLE_HALF_BLOCK(offset);
    if (emptyM) {
        TRIPLE_HALF_BLOCK(offset);
        TRIPLE_HALF_BLOCK(offset);
    }

    RHO1(input, (u32*)Y, (u32*)ad, ad_len);
    XOR_TOP_BAR_BLOCK(input, offset);
    giftb128(Y, (u8*)input, rkey);

    while (in_len > BLOCKBYTES) {
        DOUBLE_HALF_BLOCK(offset);
        if (encrypting)
            RHO((u32*)Y, (u32*)in, input, (u32*)out, BLOCKBYTES);
        else
            RHO_PRIME((u32*)Y, (u32*)in, input, (u32*)out, BLOCKBYTES);
        XOR_TOP_BAR_BLOCK(input, offset);
        giftb128(Y, (u8*)input, rkey);
        in += BLOCKBYTES;
        out += BLOCKBYTES;
        in_len -= BLOCKBYTES;
    }
    
    if (!emptyM) {
        TRIPLE_HALF_BLOCK(offset);
        if(in_len % BLOCKBYTES != 0)
            TRIPLE_HALF_BLOCK(offset);
        if (encrypting) {
            RHO((u32*)Y, (u32*)in, input, (u32*)out, in_len);
            out += in_len;
        }
        else {
            RHO_PRIME((u32*)Y, (u32*)in, input, (u32*)out, in_len);
            in += in_len;
        }
        XOR_TOP_BAR_BLOCK(input, offset);
        giftb128(Y, (u8*)input, rkey);
    }

    if (encrypting) {
        memcpy(out, Y, TAGBYTES);
        return 0;
    }
    // decrypting
    tmp0 = 0;
    for(tmp1 = 0; tmp1 < TAGBYTES; tmp1++)
        tmp0 |= in[tmp1] ^ Y[tmp1];
    return tmp0;
}

/****************************************************************************
* API required by the NIST for the LWC competition.
****************************************************************************/
int crypto_aead_encrypt(unsigned char* c, unsigned long long* clen,
                    const unsigned char* m, unsigned long long mlen,
                    const unsigned char* ad, unsigned long long adlen,
                    const unsigned char* nsec, const unsigned char* npub,
                    const unsigned char* k) {
    (void)nsec;
    *clen = mlen + TAGBYTES;
    return giftcofb_crypt(c, k, npub, ad, adlen, m, mlen, COFB_ENCRYPT);
}

/****************************************************************************
* API required by the NIST for the LWC competition.
****************************************************************************/
int crypto_aead_decrypt(unsigned char* m, unsigned long long *mlen,
                    unsigned char* nsec, const unsigned char* c,
                    unsigned long long clen, const unsigned char* ad,
                    unsigned long long adlen, const unsigned char* npub,
                    const unsigned char *k) {
    (void)nsec;
    *mlen = clen - TAGBYTES;
    return giftcofb_crypt(m, k, npub, ad, adlen, c, clen, COFB_DECRYPT);
}
