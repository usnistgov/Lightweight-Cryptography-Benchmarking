/*
 * Copyright (C) 2021 Southern Storm Software, Pty Ltd.
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

#include "xoodyak-aead.h"
#include "internal-xoodoo.h"
#include <string.h>

/**
 * \brief Rate for absorbing data into the sponge state.
 */
#define XOODYAK_ABSORB_RATE 44

/**
 * \brief Rate for squeezing data out of the sponge.
 */
#define XOODYAK_SQUEEZE_RATE 24

/**
 * \brief Phase identifier for "up" mode, which indicates that a block
 * permutation has just been performed.
 */
#define XOODYAK_PHASE_UP 0

/**
 * \brief Phase identifier for "down" mode, which indicates that data has
 * been absorbed but that a block permutation has not been done yet.
 */
#define XOODYAK_PHASE_DOWN 1

/**
 * \brief Absorbs data into the Xoodoo permutation state.
 *
 * \param state Xoodoo permutation state.
 * \param phase Points to the current phase, up or down.
 * \param data Points to the data to be absorbed.
 * \param len Length of the data to be absorbed.
 */
static void xoodyak_absorb
    (xoodoo_state_t *state, uint8_t *phase,
     const unsigned char *data, size_t len)
{
    uint8_t domain = 0x03;
    unsigned temp;
    while (len > XOODYAK_ABSORB_RATE) {
        if (*phase != XOODYAK_PHASE_UP)
            xoodoo_permute(state);
        lw_xor_block(state->B, data, XOODYAK_ABSORB_RATE);
        state->B[XOODYAK_ABSORB_RATE] ^= 0x01; /* Padding */
        state->B[sizeof(state->B) - 1] ^= domain;
        data += XOODYAK_ABSORB_RATE;
        len -= XOODYAK_ABSORB_RATE;
        domain = 0x00;
        *phase = XOODYAK_PHASE_DOWN;
    }
    temp = (unsigned)len;
    if (*phase != XOODYAK_PHASE_UP)
        xoodoo_permute(state);
    lw_xor_block(state->B, data, temp);
    state->B[temp] ^= 0x01; /* Padding */
    state->B[sizeof(state->B) - 1] ^= domain;
    *phase = XOODYAK_PHASE_DOWN;
}

int xoodyak_aead_encrypt
    (unsigned char *c, size_t *clen,
     const unsigned char *m, size_t mlen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    xoodoo_state_t state;
    uint8_t phase, domain;
    unsigned temp;

    /* Set the length of the returned ciphertext */
    *clen = mlen + XOODYAK_TAG_SIZE;

    /* Initialize the state with the key and nonce */
    memcpy(state.B, k, XOODYAK_KEY_SIZE);
    memcpy(state.B + XOODYAK_KEY_SIZE, npub, XOODYAK_NONCE_SIZE);
    state.B[XOODYAK_KEY_SIZE + XOODYAK_NONCE_SIZE] = XOODYAK_NONCE_SIZE;
    state.B[XOODYAK_KEY_SIZE + XOODYAK_NONCE_SIZE + 1] = 0x01; /* Padding */
    memset(state.B + XOODYAK_KEY_SIZE + XOODYAK_NONCE_SIZE + 2, 0,
           sizeof(state.B) - XOODYAK_KEY_SIZE - XOODYAK_NONCE_SIZE - 3);
    state.B[sizeof(state.B) - 1] = 0x02;  /* Domain separation */
    phase = XOODYAK_PHASE_DOWN;

    /* Absorb the associated data */
    xoodyak_absorb(&state, &phase, ad, adlen);

    /* Encrypt the plaintext to produce the ciphertext */
    domain = 0x80;
    while (mlen > XOODYAK_SQUEEZE_RATE) {
        state.B[sizeof(state.B) - 1] ^= domain;
        xoodoo_permute(&state);
        lw_xor_block_2_dest(c, state.B, m, XOODYAK_SQUEEZE_RATE);
        state.B[XOODYAK_SQUEEZE_RATE] ^= 0x01; /* Padding */
        c += XOODYAK_SQUEEZE_RATE;
        m += XOODYAK_SQUEEZE_RATE;
        mlen -= XOODYAK_SQUEEZE_RATE;
        domain = 0;
    }
    state.B[sizeof(state.B) - 1] ^= domain;
    xoodoo_permute(&state);
    temp = (unsigned)mlen;
    lw_xor_block_2_dest(c, state.B, m, temp);
    state.B[temp] ^= 0x01; /* Padding */
    c += temp;

    /* Generate the authentication tag */
    state.B[sizeof(state.B) - 1] ^= 0x40; /* Domain separation */
    xoodoo_permute(&state);
    memcpy(c, state.B, XOODYAK_TAG_SIZE);
    return 0;
}

int xoodyak_aead_decrypt
    (unsigned char *m, size_t *mlen,
     const unsigned char *c, size_t clen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    xoodoo_state_t state;
    uint8_t phase, domain;
    unsigned temp;
    unsigned char *mtemp = m;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < XOODYAK_TAG_SIZE)
        return -1;
    *mlen = clen - XOODYAK_TAG_SIZE;

    /* Initialize the state with the key and nonce */
    memcpy(state.B, k, XOODYAK_KEY_SIZE);
    memcpy(state.B + XOODYAK_KEY_SIZE, npub, XOODYAK_NONCE_SIZE);
    state.B[XOODYAK_KEY_SIZE + XOODYAK_NONCE_SIZE] = XOODYAK_NONCE_SIZE;
    state.B[XOODYAK_KEY_SIZE + XOODYAK_NONCE_SIZE + 1] = 0x01; /* Padding */
    memset(state.B + XOODYAK_KEY_SIZE + XOODYAK_NONCE_SIZE + 2, 0,
           sizeof(state.B) - XOODYAK_KEY_SIZE - XOODYAK_NONCE_SIZE - 3);
    state.B[sizeof(state.B) - 1] = 0x02;  /* Domain separation */
    phase = XOODYAK_PHASE_DOWN;

    /* Absorb the associated data */
    xoodyak_absorb(&state, &phase, ad, adlen);

    /* Decrypt the ciphertext to produce the plaintext */
    domain = 0x80;
    clen -= XOODYAK_TAG_SIZE;
    while (clen > XOODYAK_SQUEEZE_RATE) {
        state.B[sizeof(state.B) - 1] ^= domain;
        xoodoo_permute(&state);
        lw_xor_block_swap(m, state.B, c, XOODYAK_SQUEEZE_RATE);
        state.B[XOODYAK_SQUEEZE_RATE] ^= 0x01; /* Padding */
        c += XOODYAK_SQUEEZE_RATE;
        m += XOODYAK_SQUEEZE_RATE;
        clen -= XOODYAK_SQUEEZE_RATE;
        domain = 0;
    }
    state.B[sizeof(state.B) - 1] ^= domain;
    xoodoo_permute(&state);
    temp = (unsigned)clen;
    lw_xor_block_swap(m, state.B, c, temp);
    state.B[temp] ^= 0x01; /* Padding */
    c += temp;

    /* Check the authentication tag */
    state.B[sizeof(state.B) - 1] ^= 0x40; /* Domain separation */
    xoodoo_permute(&state);
    return aead_check_tag(mtemp, *mlen, state.B, c, XOODYAK_TAG_SIZE);
}
