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

#include "romulus-t-aead.h"
#include "romulus-hash.h"
#include "internal-romulus.h"
#include "internal-skinny-plus.h"
#include "internal-util.h"
#include <string.h>

/**
 * \brief Zero nonce value.
 */
static unsigned char const romulus_zero_nonce[16] = {0};

/**
 * \brief Updates a Romulus-H state with data padded to a 16 byte boundary.
 *
 * \param state Romulus-H state to be updated.
 * \param in Points to the input data to hash.
 * \param inlen Length of the input data in bytes.
 */
static void romulus_hash_update_padded
    (romulus_hash_state_t *state, const unsigned char *in, size_t inlen)
{
    unsigned char padding[16] = {0};
    size_t offset;
    romulus_hash_update(state, in, inlen);
    offset = inlen % 16U;
    padding[15] = (unsigned char)offset;
    romulus_hash_update(state, padding + offset, sizeof(padding) - offset);
}

int romulus_t_aead_encrypt
    (unsigned char *c, size_t *clen,
     const unsigned char *m, size_t mlen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    skinny_plus_key_schedule_t ks;
    unsigned char S[32];
    romulus_hash_state_t hash;

    /* Set the length of the returned ciphertext */
    *clen = mlen + ROMULUS_T_TAG_SIZE;

    /* Hash the associated data */
    romulus_hash_init(&hash);
    if (adlen)
        romulus_hash_update_padded(&hash, ad, adlen);

    /* Encrypt the plaintext to produce the ciphertext */
    memset(ks.TK1, 0, sizeof(ks.TK1));
    if (mlen) {
        romulus_set_domain(&ks, 66);
        skinny_plus_init_without_tk1(&ks, romulus_zero_nonce, k);
        skinny_plus_encrypt(&ks, S, npub);
        ks.TK1[0] = 0x01;
        while (mlen >= 16) {
            skinny_plus_init_without_tk1(&ks, romulus_zero_nonce, S);
            romulus_set_domain(&ks, 64);
            skinny_plus_encrypt(&ks, S, npub);
            lw_xor_block_2_src(c, m, S, 16);
            romulus_set_domain(&ks, 65);
            skinny_plus_encrypt(&ks, S, npub);
            romulus_hash_update(&hash, c, 16);
            romulus_update_counter(ks.TK1);
            c += 16;
            m += 16;
            mlen -= 16;
        }
        if (mlen) {
            skinny_plus_init_without_tk1(&ks, romulus_zero_nonce, S);
            romulus_set_domain(&ks, 64);
            skinny_plus_encrypt(&ks, S, npub);
            lw_xor_block_2_src(c, m, S, mlen);
            romulus_update_counter(ks.TK1);
        }
        romulus_hash_update_padded(&hash, c, mlen);
    } else {
        ks.TK1[0] = 0x01;
    }

    /* Hash the nonce and the final LFSR counter value */
    romulus_hash_update(&hash, npub, ROMULUS_T_NONCE_SIZE);
    romulus_hash_update(&hash, ks.TK1, 7);

    /* Generate the authentication tag */
    romulus_hash_finalize(&hash, S);
    memset(ks.TK1, 0, sizeof(ks.TK1));
    romulus_set_domain(&ks, 68);
    skinny_plus_init_without_tk1(&ks, S + 16, k);
    skinny_plus_encrypt(&ks, c + mlen, S);
    return 0;
}

int romulus_t_aead_decrypt
    (unsigned char *m, size_t *mlen,
     const unsigned char *c, size_t clen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    unsigned char *mstart = m;
    skinny_plus_key_schedule_t ks;
    unsigned char S[32];
    romulus_hash_state_t hash;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < ROMULUS_T_TAG_SIZE)
        return -1;
    *mlen = clen - ROMULUS_T_TAG_SIZE;

    /* Hash the associated data */
    romulus_hash_init(&hash);
    if (adlen)
        romulus_hash_update_padded(&hash, ad, adlen);

    /* Decrypt the ciphertext to produce the plaintext */
    memset(ks.TK1, 0, sizeof(ks.TK1));
    clen -= ROMULUS_T_TAG_SIZE;
    if (clen) {
        romulus_set_domain(&ks, 66);
        skinny_plus_init_without_tk1(&ks, romulus_zero_nonce, k);
        skinny_plus_encrypt(&ks, S, npub);
        ks.TK1[0] = 0x01;
        while (clen >= 16) {
            romulus_hash_update(&hash, c, 16);
            skinny_plus_init_without_tk1(&ks, romulus_zero_nonce, S);
            romulus_set_domain(&ks, 64);
            skinny_plus_encrypt(&ks, S, npub);
            lw_xor_block_2_src(m, c, S, 16);
            romulus_set_domain(&ks, 65);
            skinny_plus_encrypt(&ks, S, npub);
            romulus_update_counter(ks.TK1);
            m += 16;
            c += 16;
            clen -= 16;
        }
        romulus_hash_update_padded(&hash, c, clen);
        if (clen) {
            skinny_plus_init_without_tk1(&ks, romulus_zero_nonce, S);
            romulus_set_domain(&ks, 64);
            skinny_plus_encrypt(&ks, S, npub);
            lw_xor_block_2_src(m, c, S, clen);
            romulus_update_counter(ks.TK1);
        }
    } else {
        ks.TK1[0] = 0x01;
    }

    /* Hash the nonce and the final LFSR counter value */
    romulus_hash_update(&hash, npub, ROMULUS_T_NONCE_SIZE);
    romulus_hash_update(&hash, ks.TK1, 7);

    /* Check the authentication tag */
    romulus_hash_finalize(&hash, S);
    memset(ks.TK1, 0, sizeof(ks.TK1));
    romulus_set_domain(&ks, 68);
    skinny_plus_init_without_tk1(&ks, S + 16, k);
    skinny_plus_encrypt(&ks, S, S);
    return aead_check_tag(mstart, *mlen, S, c + clen, ROMULUS_T_TAG_SIZE);
}
