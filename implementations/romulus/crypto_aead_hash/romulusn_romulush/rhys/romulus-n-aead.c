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

#include "romulus-n-aead.h"
#include "internal-romulus.h"
#include "internal-skinny-plus.h"
#include "internal-util.h"
#include <string.h>

/**
 * \brief Process the asssociated data for Romulus-N.
 *
 * \param ks Points to the key schedule.
 * \param S The rolling Romulus state.
 * \param k Points to the key.
 * \param npub Points to the nonce.
 * \param ad Points to the associated data.
 * \param adlen Length of the associated data in bytes.
 */
static void romulus_n_process_ad
    (skinny_plus_key_schedule_t *ks,
     unsigned char S[16], const unsigned char *k, const unsigned char *npub,
     const unsigned char *ad, size_t adlen)
{
    unsigned char temp;

    /* Initialise the LFSR counter in TK1 */
    ks->TK1[0] = 0x01;
    memset(ks->TK1 + 1, 0, 15);

    /* Handle the special case of no associated data */
    if (adlen == 0) {
        romulus_update_counter(ks->TK1);
        romulus_set_domain(ks, 0x1A);
        skinny_plus_init_without_tk1(ks, npub, k);
        skinny_plus_encrypt(ks, S, S);
        return;
    }

    /* Process all double blocks except the last */
    romulus_set_domain(ks, 0x08);
    while (adlen > 32) {
        romulus_update_counter(ks->TK1);
        lw_xor_block(S, ad, 16);
        skinny_plus_init_without_tk1(ks, ad + 16, k);
        skinny_plus_encrypt(ks, S, S);
        romulus_update_counter(ks->TK1);
        ad += 32;
        adlen -= 32;
    }

    /* Pad and process the left-over blocks */
    romulus_update_counter(ks->TK1);
    temp = (unsigned)adlen;
    if (temp == 32) {
        /* Left-over complete double block */
        lw_xor_block(S, ad, 16);
        skinny_plus_init_without_tk1(ks, ad + 16, k);
        skinny_plus_encrypt(ks, S, S);
        romulus_update_counter(ks->TK1);
        romulus_set_domain(ks, 0x18);
    } else if (temp > 16) {
        /* Left-over partial double block */
        unsigned char pad[16];
        temp -= 16;
        lw_xor_block(S, ad, 16);
        memcpy(pad, ad + 16, temp);
        memset(pad + temp, 0, 15 - temp);
        pad[15] = temp;
        skinny_plus_init_without_tk1(ks, pad, k);
        skinny_plus_encrypt(ks, S, S);
        romulus_update_counter(ks->TK1);
        romulus_set_domain(ks, 0x1A);
    } else if (temp == 16) {
        /* Left-over complete single block */
        lw_xor_block(S, ad, temp);
        romulus_set_domain(ks, 0x18);
    } else {
        /* Left-over partial single block */
        lw_xor_block(S, ad, temp);
        S[15] ^= temp;
        romulus_set_domain(ks, 0x1A);
    }
    skinny_plus_init_without_tk1(ks, npub, k);
    skinny_plus_encrypt(ks, S, S);
}

/**
 * \brief Encrypts a plaintext message with Romulus-N.
 *
 * \param ks Points to the key schedule.
 * \param S The rolling Romulus state.
 * \param c Points to the buffer to receive the ciphertext.
 * \param m Points to the buffer containing the plaintext.
 * \param mlen Length of the plaintext in bytes.
 */
static void romulus_n_encrypt
    (skinny_plus_key_schedule_t *ks, unsigned char S[16],
     unsigned char *c, const unsigned char *m, size_t mlen)
{
    unsigned temp;

    /* Handle the special case of no plaintext */
    if (mlen == 0) {
        romulus_update_counter(ks->TK1);
        romulus_set_domain(ks, 0x15);
        skinny_plus_encrypt(ks, S, S);
        return;
    }

    /* Process all blocks except the last */
    romulus_set_domain(ks, 0x04);
    while (mlen > 16) {
        romulus_rho(S, c, m);
        romulus_update_counter(ks->TK1);
        skinny_plus_encrypt(ks, S, S);
        c += 16;
        m += 16;
        mlen -= 16;
    }

    /* Pad and process the last block */
    temp = (unsigned)mlen;
    romulus_update_counter(ks->TK1);
    if (temp < 16) {
        romulus_rho_short(S, c, m, temp);
        romulus_set_domain(ks, 0x15);
    } else {
        romulus_rho(S, c, m);
        romulus_set_domain(ks, 0x14);
    }
    skinny_plus_encrypt(ks, S, S);
}

/**
 * \brief Decrypts a ciphertext message with Romulus-N.
 *
 * \param ks Points to the key schedule.
 * \param S The rolling Romulus state.
 * \param m Points to the buffer to receive the plaintext.
 * \param c Points to the buffer containing the ciphertext.
 * \param mlen Length of the plaintext in bytes.
 */
static void romulus_n_decrypt
    (skinny_plus_key_schedule_t *ks, unsigned char S[16],
     unsigned char *m, const unsigned char *c, size_t mlen)
{
    unsigned temp;

    /* Handle the special case of no ciphertext */
    if (mlen == 0) {
        romulus_update_counter(ks->TK1);
        romulus_set_domain(ks, 0x15);
        skinny_plus_encrypt(ks, S, S);
        return;
    }

    /* Process all blocks except the last */
    romulus_set_domain(ks, 0x04);
    while (mlen > 16) {
        romulus_rho_inverse(S, m, c);
        romulus_update_counter(ks->TK1);
        skinny_plus_encrypt(ks, S, S);
        c += 16;
        m += 16;
        mlen -= 16;
    }

    /* Pad and process the last block */
    temp = (unsigned)mlen;
    romulus_update_counter(ks->TK1);
    if (temp < 16) {
        romulus_rho_inverse_short(S, m, c, temp);
        romulus_set_domain(ks, 0x15);
    } else {
        romulus_rho_inverse(S, m, c);
        romulus_set_domain(ks, 0x14);
    }
    skinny_plus_encrypt(ks, S, S);
}

int romulus_n_aead_encrypt
    (unsigned char *c, size_t *clen,
     const unsigned char *m, size_t mlen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    skinny_plus_key_schedule_t ks;
    unsigned char S[16];

    /* Set the length of the returned ciphertext */
    *clen = mlen + ROMULUS_N_TAG_SIZE;

    /* Process the associated data */
    memset(S, 0, sizeof(S));
    romulus_n_process_ad(&ks, S, k, npub, ad, adlen);

    /* Re-initialize the key schedule with the key and nonce */
    romulus_schedule_init(&ks, k, npub);

    /* Encrypts the plaintext to produce the ciphertext */
    romulus_n_encrypt(&ks, S, c, m, mlen);

    /* Generate the authentication tag */
    romulus_generate_tag(c + mlen, S);
    return 0;
}

int romulus_n_aead_decrypt
    (unsigned char *m, size_t *mlen,
     const unsigned char *c, size_t clen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    skinny_plus_key_schedule_t ks;
    unsigned char S[16];

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < ROMULUS_N_TAG_SIZE)
        return -1;
    *mlen = clen - ROMULUS_N_TAG_SIZE;

    /* Process the associated data */
    memset(S, 0, sizeof(S));
    romulus_n_process_ad(&ks, S, k, npub, ad, adlen);

    /* Re-initialize the key schedule with the key and nonce */
    romulus_schedule_init(&ks, k, npub);

    /* Decrypt the ciphertext to produce the plaintext */
    clen -= ROMULUS_N_TAG_SIZE;
    romulus_n_decrypt(&ks, S, m, c, clen);

    /* Check the authentication tag */
    romulus_generate_tag(S, S);
    return aead_check_tag(m, clen, S, c + clen, ROMULUS_N_TAG_SIZE);
}
