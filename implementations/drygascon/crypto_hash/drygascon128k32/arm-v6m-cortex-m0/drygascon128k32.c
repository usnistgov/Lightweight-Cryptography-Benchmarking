/*
 * Copyright (C) 2020 Southern Storm Software, Pty Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */
#include "drygascon128k32.h"
#include "drygascon128core.h"
#include <stdint.h>
#include <string.h>

// Compilation options:
// #define AEAD_DETECT_OVERLAP
//      detect if in==out and handle this case correctly
//      NOTE: if in!=out but there is still some overlap then the behavior is undefined
// #define DRYGASCON_DEBUG
//      Print the state at various stages of the computation


#ifdef DRYGASCON_DEBUG
    #include <stdio.h>
    static void println_bytes(const char*const msg,const void*const buf,unsigned int len){
        printf("%s",msg);
        const uint8_t*const buf8=(const uint8_t*const)buf;
        for(unsigned int i=0;i<len;i++){
            printf("%02x ",buf8[i]);
        }
        printf("\n");
    }
#endif

/**
 * \brief Size of the GASCON-128 permutation state in bytes.
 */
#define GASCON128_STATE_SIZE 40

/**
 * \brief Rate of absorption and squeezing for DrySPONGE128.
 */
#define DRYSPONGE128_RATE 16

/**
 * \brief Size of the "x" value for DrySPONGE128.
 */
#define DRYSPONGE128_XSIZE 16

/**
 * \brief Normal number of rounds for DrySPONGE128 when absorbing
 * and squeezing data.
 */
#define DRYSPONGE128_ROUNDS 7

/**
 * \brief Number of rounds for DrySPONGE128 during initialization.
 */
#define DRYSPONGE128_INIT_ROUNDS 11

/**
 * \brief Number of rounds for DrySPONGE256 during initialization.
 */
#define DRYSPONGE256_INIT_ROUNDS 12

/**
 * \brief DrySPONGE128 domain bit for a padded block.
 */
#define DRYDOMAIN128_PADDED (1 << 0)

/**
 * \brief DrySPONGE128 domain bit for a final block.
 */
#define DRYDOMAIN128_FINAL (1 << 1)

/**
 * \brief DrySPONGE128 domain value for processing the nonce.
 */
#define DRYDOMAIN128_NONCE (1 << 2)

/**
 * \brief DrySPONGE128 domain value for processing the associated data.
 */
#define DRYDOMAIN128_ASSOC_DATA (2 << 2)

/**
 * \brief DrySPONGE128 domain value for processing the message.
 */
#define DRYDOMAIN128_MESSAGE (3 << 2)

/**
 * \brief Internal state of the GASCON-128 permutation.
 */
typedef union
{
    uint64_t S[GASCON128_STATE_SIZE / 8];   /**< 64-bit words of the state */
    uint32_t W[GASCON128_STATE_SIZE / 4];   /**< 32-bit words of the state */
    uint8_t B[GASCON128_STATE_SIZE];        /**< Bytes of the state */

} gascon128_state_t;

/**
 * \brief Structure of a rate block for DrySPONGE128.
 */
typedef union
{
    uint64_t S[DRYSPONGE128_RATE / 8];      /**< 64-bit words of the rate */
    uint32_t W[DRYSPONGE128_RATE / 4];      /**< 32-bit words of the rate */
    uint8_t B[DRYSPONGE128_RATE];           /**< Bytes of the rate */

} drysponge128_rate_t;

/**
 * \brief Structure of the "x" value for DrySPONGE128.
 */
typedef union
{
    uint64_t S[DRYSPONGE128_XSIZE / 8]; /**< 64-bit words of the rate */
    uint32_t W[DRYSPONGE128_XSIZE / 4]; /**< 32-bit words of the rate */
    uint8_t B[DRYSPONGE128_XSIZE];      /**< Bytes of the rate */

} __attribute__((aligned(16))) drysponge128_x_t;

/**
 * \brief Structure of the rolling DrySPONGE128 state.
 */
typedef struct
{
	gascon128_state_t c;        /**< GASCON-128 state for the capacity */
    uint32_t domain;            /**< Domain value to mix on next F call */
    uint32_t rounds;            /**< Number of rounds for next G call */
    drysponge128_rate_t r;      /**< Buffer for a rate block of data */
    drysponge128_x_t x;         /**< "x" value for the sponge */
} __attribute__((aligned(16))) drysponge128_state_t;

// XOR two source byte buffers and put the result in a destination buffer
#define lw_xor_block_2_src(dest, src1, src2, len) \
    do { \
        unsigned char *_dest = (dest); \
        const unsigned char *_src1 = (src1); \
        const unsigned char *_src2 = (src2); \
        unsigned _len = (len); \
        while (_len > 0) { \
            *_dest++ = *_src1++ ^ *_src2++; \
            --_len; \
        } \
    } while (0)

void DRYGASCON_G_OPT(uint64_t* state, uint32_t rounds);

#define drysponge128_g(state) DRYGASCON_G_OPT((uint64_t*)(state),(state)->rounds)

void DRYGASCON_F_OPT(drysponge128_state_t *state, const unsigned char *input,unsigned int ds, unsigned int rounds);

#ifdef DRYGASCON_DEBUG
    #define DRYGASCON_PRINT_F_ENTRY(state,input) do{\
        printf("domain=0x%lx, rounds=%lu\n",(state)->domain,(state)->rounds);\
        println_bytes("state: ",(state),sizeof(drysponge128_state_t));\
        println_bytes("input: ",(input),DRYSPONGE128_RATE);\
    }while(0)
#else
    #define DRYGASCON_PRINT_F_ENTRY(state,input)
#endif

#define drygascon128_f_full(state,input) do{\
        DRYGASCON_PRINT_F_ENTRY((state),(input));\
        DRYGASCON_F_OPT(state, input,(state)->domain,(state)->rounds);\
        (state)->domain = 0;\
    } while(0)

static void drygascon128_f_wrap(drysponge128_state_t *state, const unsigned char *input, unsigned len){
    drysponge128_rate_t padded;
    const unsigned char*in;
    if (len < DRYSPONGE128_RATE) {
        memcpy(padded.B, input, len);
        padded.B[len] = 0x01;
        memset(padded.B + len + 1, 0, DRYSPONGE128_RATE - len - 1);
        in=padded.B;
        state->domain |= DRYDOMAIN128_PADDED;
    } else {
        in=input;
    }
    drygascon128_f_full(state, in);
}

static void drysponge128_setup_k32(drysponge128_state_t *state, const unsigned char *key){
    // Fill the GASCON-128 state with repeated copies of the key
    memcpy(state->c.B, key, 16);
    memcpy(state->c.B + 16, key, 16);
    memcpy(state->c.B + 32, key, 8);
    
    // Fill X with the 16 last bytes of the key
    memcpy(state->x.B, key+16, sizeof(state->x));
}

/**
 * \brief Set up a DrySPONGE128 state to begin encryption or decryption.
 *
 * \param state The DrySPONGE128 state.
 * \param key Points to the 32 bytes of the key.
 * \param nonce Points to the 16 bytes of the nonce.
 * \param final_block Non-zero if after key setup there will be no more blocks.
 */
static void drysponge128_setup
    (drysponge128_state_t *state, const unsigned char *key, unsigned int keysize,
     const unsigned char *nonce, int final_block){
    drysponge128_setup_k32(state, key);

    // Absorb the nonce into the state with an increased number of rounds
    state->rounds = DRYSPONGE128_INIT_ROUNDS;
    state->domain = DRYDOMAIN128_NONCE;
    if (final_block)
        state->domain |= DRYDOMAIN128_FINAL;
    drygascon128_f_full(state, nonce);

    // Set up the normal number of rounds for future operations
    state->rounds = DRYSPONGE128_ROUNDS;
}

/**
 * \brief Processes associated data for DryGASCON128.
 *
 * \param state DrySPONGE128 sponge state.
 * \param ad Points to the associated data.
 * \param adlen Length of the associated data, must not be zero.
 * \param finalize Non-zero to finalize packet processing because
 * the message is zero-length.
 */
static void drygascon128_process_ad
    (drysponge128_state_t *state, const unsigned char *ad,
     unsigned long long adlen, int finalize){
    // Process all blocks except the last one
    while (adlen > DRYSPONGE128_RATE) {
        drygascon128_f_full(state, ad);
        ad += DRYSPONGE128_RATE;
        adlen -= DRYSPONGE128_RATE;
    }

    // Process the last block with domain separation and padding
    state->domain = DRYDOMAIN128_ASSOC_DATA;
    if (finalize)
        state->domain |= DRYDOMAIN128_FINAL;
    drygascon128_f_wrap(state, ad, (unsigned)adlen);
}

static int drygascon128_aead_encrypt_core
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
	 unsigned int keysize,
     const unsigned char *npub,
     const unsigned char *k){
    drysponge128_state_t state;

    // Set the length of the returned ciphertext
    *clen = mlen + DRYGASCON128_TAG_SIZE;

    // Initialize the sponge state with the key and nonce
    drysponge128_setup(&state, k, keysize, npub, adlen == 0 && mlen == 0);

    // Process the associated data
    if (adlen > 0)
        drygascon128_process_ad(&state, ad, adlen, mlen == 0);

    // Encrypt the plaintext to produce the ciphertext
    if (mlen > 0) {
        #ifdef AEAD_DETECT_OVERLAP
        if(c==m) {
            // Deal with in-place encryption case
            drysponge128_rate_t tmp; 
            unsigned char *m2 = (unsigned char *)&tmp;
            /* Processs all blocks except the last one */
            while (mlen > DRYSPONGE128_RATE) {
                memcpy(m2,m,DRYSPONGE128_RATE);
                lw_xor_block_2_src(c, m, state.r.B, DRYSPONGE128_RATE);
                drygascon128_f_full(&state, m2);
                c += DRYSPONGE128_RATE;
                m += DRYSPONGE128_RATE;
                mlen -= DRYSPONGE128_RATE;
            }
        }else{
        #endif
            // Processs all blocks except the last one
            while (mlen > DRYSPONGE128_RATE) {
                lw_xor_block_2_src(c, m, state.r.B, DRYSPONGE128_RATE);
                drygascon128_f_full(&state, m);
                c += DRYSPONGE128_RATE;
                m += DRYSPONGE128_RATE;
                mlen -= DRYSPONGE128_RATE;
            }
        #ifdef AEAD_DETECT_OVERLAP
        }
        #endif

        // Process the last block with domain separation and padding
        state.domain = DRYDOMAIN128_MESSAGE | DRYDOMAIN128_FINAL;
        #ifdef AEAD_DETECT_OVERLAP
        if(c==m) {
            // Deal with in-place encryption case
            drysponge128_rate_t tmp; 
            unsigned char *m2 = (unsigned char *)&tmp;
            memcpy(m2,m,DRYSPONGE128_RATE);
            lw_xor_block_2_src(c, m, state.r.B, (unsigned)mlen);
            drygascon128_f_wrap(&state, m2, (unsigned)mlen);
        }else{
        #endif
            lw_xor_block_2_src(c, m, state.r.B, (unsigned)mlen);
            drygascon128_f_wrap(&state, m, (unsigned)mlen);
        #ifdef AEAD_DETECT_OVERLAP
        }
        #endif
        c += mlen;
    }

    // Generate the authentication tag
    memcpy(c, state.r.B, DRYGASCON128_TAG_SIZE);
    return 0;
}

static int drygascon128_aead_decrypt_core
    (unsigned char *m, unsigned long long *mlen,
     unsigned int keysize,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k){
    drysponge128_state_t state;

    // Validate the ciphertext length and set the return "mlen" value
    if (clen < DRYGASCON128_TAG_SIZE)
        return -1;
    *mlen = clen - DRYGASCON128_TAG_SIZE;

    // Initialize the sponge state with the key and nonce
    clen -= DRYGASCON128_TAG_SIZE;
    drysponge128_setup(&state, k, keysize, npub, adlen == 0 && clen == 0);

    // Process the associated data
    if (adlen > 0)
        drygascon128_process_ad(&state, ad, adlen, clen == 0);

    // Decrypt the ciphertext to produce the plaintext
    if (clen > 0) {
        // Processs all blocks except the last one
        while (clen > DRYSPONGE128_RATE) {
            lw_xor_block_2_src(m, c, state.r.B, DRYSPONGE128_RATE);
            drygascon128_f_full(&state, m);
            c += DRYSPONGE128_RATE;
            m += DRYSPONGE128_RATE;
            clen -= DRYSPONGE128_RATE;
        }

        // Process the last block with domain separation and padding
        state.domain = DRYDOMAIN128_MESSAGE | DRYDOMAIN128_FINAL;
        lw_xor_block_2_src(m, c, state.r.B, (unsigned)clen);
        drygascon128_f_wrap(&state, m, (unsigned)clen);
        c += (unsigned)clen;
    }

    // Check the authentication tag
    return memcmp(state.r.B, c, DRYGASCON128_TAG_SIZE);
}

int drygascon128k32_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k){
    (void)nsec;
	return drygascon128_aead_encrypt_core(c,clen,m,mlen,ad,adlen,32,npub,k);
}

int drygascon128k32_aead_decrypt
	(unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k){
    (void)nsec;
	return drygascon128_aead_decrypt_core(m,mlen,32,c,clen,ad,adlen,npub,k);
}

static unsigned char const drygascon128_hash_init_k32[] = {
    0x24, 0x3f, 0x6a, 0x88, 0x85, 0xa3, 0x08, 0xd3,
    0x13, 0x19, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x44,
    0xa4, 0x09, 0x38, 0x22, 0x29, 0x9f, 0x31, 0xd0,
    0x08, 0x2e, 0xfa, 0x98, 0xec, 0x4e, 0x6c, 0x89
};

int drygascon128_hash
    (unsigned char *out, const unsigned char *in, unsigned long long inlen){
    drysponge128_state_t state;
    drysponge128_setup_k32(&state, drygascon128_hash_init_k32);
    state.domain = 0;
    state.rounds = DRYSPONGE128_ROUNDS;
    drygascon128_process_ad(&state, in, inlen, 1);
    memcpy(out, state.r.B, DRYSPONGE128_RATE);
    drysponge128_g(&state);
    memcpy(out + 16, state.r.B, DRYSPONGE128_RATE);
    return 0;
}
