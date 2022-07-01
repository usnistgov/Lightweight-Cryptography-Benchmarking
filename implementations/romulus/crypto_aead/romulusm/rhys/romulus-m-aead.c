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

#include "romulus-m-aead.h"
#include "internal-romulus.h"
#include "internal-skinny-plus.h"
#include "internal-util.h"
#include <string.h>

/**
 * \brief Determine the domain separation value to use on the last
 * block of the associated data processing.
 *
 * \param adlen Length of the associated data in bytes.
 * \param mlen Length of the message in bytes.
 * \param t Size of the second half of a double block; 12 or 16.
 *
 * \return The domain separation bits to use to finalize the last block.
 */
static uint8_t romulus_m_final_ad_domain
    (size_t adlen, size_t mlen, unsigned t)
{
    uint8_t domain = 0;
    unsigned split = 16U;
    unsigned leftover;

    /* Determine which domain bits we need based on the length of the ad */
    if (adlen == 0) {
        /* No associated data, so only 1 block with padding */
        domain ^= 0x02;
        split = t;
    } else {
        /* Even or odd associated data length? */
        leftover = (unsigned)(adlen % (16U + t));
        if (leftover == 0) {
            /* Even with a full double block at the end */
            domain ^= 0x08;
        } else if (leftover < split) {
            /* Odd with a partial single block at the end */
            domain ^= 0x02;
            split = t;
        } else if (leftover > split) {
            /* Even with a partial double block at the end */
            domain ^= 0x0A;
        } else {
            /* Odd with a full single block at the end */
            split = t;
        }
    }

    /* Determine which domain bits we need based on the length of the message */
    if (mlen == 0) {
        /* No message, so only 1 block with padding */
        domain ^= 0x01;
    } else {
        /* Even or odd message length? */
        leftover = (unsigned)(mlen % (16U + t));
        if (leftover == 0) {
            /* Even with a full double block at the end */
            domain ^= 0x04;
        } else if (leftover < split) {
            /* Odd with a partial single block at the end */
            domain ^= 0x01;
        } else if (leftover > split) {
            /* Even with a partial double block at the end */
            domain ^= 0x05;
        }
    }
    return domain;
}

/**
 * \brief Process the asssociated data for Romulus-M.
 *
 * \param ks Points to the key schedule.
 * \param S The rolling Romulus state.
 * \param k Points to the key.
 * \param npub Points to the nonce.
 * \param ad Points to the associated data.
 * \param adlen Length of the associated data in bytes.
 * \param m Points to the message plaintext.
 * \param mlen Length of the message plaintext.
 */
static void romulus_m_process_ad
    (skinny_plus_key_schedule_t *ks,
     unsigned char S[16], const unsigned char *k, const unsigned char *npub,
     const unsigned char *ad, size_t adlen,
     const unsigned char *m, size_t mlen)
{
    unsigned char pad[16];
    uint8_t final_domain = 0x30;
    unsigned temp;

    /* Determine the domain separator to use on the final block */
    final_domain ^= romulus_m_final_ad_domain(adlen, mlen, 16);

    /* Initialise the LFSR counter in TK1 */
    ks->TK1[0] = 0x01;
    memset(ks->TK1 + 1, 0, 15);

    /* Handle the special case of no associated data */
    /* Process all associated data double blocks except the last */
    romulus_set_domain(ks, 0x28);
    while (adlen > 32) {
        romulus_update_counter(ks->TK1);
        lw_xor_block(S, ad, 16);
        skinny_plus_init_without_tk1(ks, ad + 16, k);
        skinny_plus_encrypt(ks, S, S);
        romulus_update_counter(ks->TK1);
        ad += 32;
        adlen -= 32;
    }

    /* Process the last associated data double block */
    temp = (unsigned)adlen;
    if (temp == 32) {
        /* Last associated data double block is full */
        romulus_update_counter(ks->TK1);
        lw_xor_block(S, ad, 16);
        skinny_plus_init_without_tk1(ks, ad + 16, k);
        skinny_plus_encrypt(ks, S, S);
        romulus_update_counter(ks->TK1);
    } else if (temp > 16) {
        /* Last associated data double block is partial */
        temp -= 16;
        romulus_update_counter(ks->TK1);
        lw_xor_block(S, ad, 16);
        memcpy(pad, ad + 16, temp);
        memset(pad + temp, 0, sizeof(pad) - temp - 1);
        pad[sizeof(pad) - 1] = (unsigned char)temp;
        skinny_plus_init_without_tk1(ks, pad, k);
        skinny_plus_encrypt(ks, S, S);
        romulus_update_counter(ks->TK1);
    } else {
        /* Last associated data block is single.  Needs to be combined
         * with the first block of the message payload */
        romulus_set_domain(ks, 0x2C);
        romulus_update_counter(ks->TK1);
        if (temp == 16) {
            lw_xor_block(S, ad, 16);
        } else {
            lw_xor_block(S, ad, temp);
            S[15] ^= (unsigned char)temp;
        }
        if (mlen > 16) {
            skinny_plus_init_without_tk1(ks, m, k);
            skinny_plus_encrypt(ks, S, S);
            romulus_update_counter(ks->TK1);
            m += 16;
            mlen -= 16;
        } else if (mlen == 16) {
            skinny_plus_init_without_tk1(ks, m, k);
            skinny_plus_encrypt(ks, S, S);
            m += 16;
            mlen -= 16;
        } else {
            temp = (unsigned)mlen;
            memcpy(pad, m, temp);
            memset(pad + temp, 0, sizeof(pad) - temp - 1);
            pad[sizeof(pad) - 1] = (unsigned char)temp;
            skinny_plus_init_without_tk1(ks, pad, k);
            skinny_plus_encrypt(ks, S, S);
            mlen = 0;
        }
    }

    /* Process all message double blocks except the last */
    romulus_set_domain(ks, 0x2C);
    while (mlen > 32) {
        romulus_update_counter(ks->TK1);
        lw_xor_block(S, m, 16);
        skinny_plus_init_without_tk1(ks, m + 16, k);
        skinny_plus_encrypt(ks, S, S);
        romulus_update_counter(ks->TK1);
        m += 32;
        mlen -= 32;
    }

    /* Process the last message double block */
    temp = (unsigned)mlen;
    if (temp == 32) {
        /* Last message double block is full */
        romulus_update_counter(ks->TK1);
        lw_xor_block(S, m, 16);
        skinny_plus_init_without_tk1(ks, m + 16, k);
        skinny_plus_encrypt(ks, S, S);
    } else if (temp > 16) {
        /* Last message double block is partial */
        temp -= 16;
        romulus_update_counter(ks->TK1);
        lw_xor_block(S, m, 16);
        memcpy(pad, m + 16, temp);
        memset(pad + temp, 0, sizeof(pad) - temp - 1);
        pad[sizeof(pad) - 1] = (unsigned char)temp;
        skinny_plus_init_without_tk1(ks, pad, k);
        skinny_plus_encrypt(ks, S, S);
    } else if (temp == 16) {
        /* Last message single block is full */
        lw_xor_block(S, m, 16);
    } else if (temp > 0) {
        /* Last message single block is partial */
        lw_xor_block(S, m, temp);
        S[15] ^= (unsigned char)temp;
    }

    /* Process the last partial block */
    romulus_set_domain(ks, final_domain);
    romulus_update_counter(ks->TK1);
    skinny_plus_init_without_tk1(ks, npub, k);
    skinny_plus_encrypt(ks, S, S);
}

/**
 * \brief Encrypts a plaintext message with Romulus-M.
 *
 * \param ks Points to the key schedule.
 * \param S The rolling Romulus state.
 * \param c Points to the buffer to receive the ciphertext.
 * \param m Points to the buffer containing the plaintext.
 * \param mlen Length of the plaintext in bytes.
 */
static void romulus_m_encrypt
    (skinny_plus_key_schedule_t *ks, unsigned char S[16],
     unsigned char *c, const unsigned char *m, size_t mlen)
{
    /* Nothing to do if the message is empty */
    if (!mlen)
        return;

    /* Process all block except the last */
    romulus_set_domain(ks, 0x24);
    while (mlen > 16) {
        skinny_plus_encrypt(ks, S, S);
        romulus_rho(S, c, m);
        romulus_update_counter(ks->TK1);
        c += 16;
        m += 16;
        mlen -= 16;
    }

    /* Handle the last block */
    skinny_plus_encrypt(ks, S, S);
    romulus_rho_short(S, c, m, (unsigned)mlen);
}

/**
 * \brief Decrypts a ciphertext message with Romulus-M.
 *
 * \param ks Points to the key schedule.
 * \param S The rolling Romulus state.
 * \param m Points to the buffer to receive the plaintext.
 * \param c Points to the buffer containing the ciphertext.
 * \param mlen Length of the plaintext in bytes.
 */
static void romulus_m_decrypt
    (skinny_plus_key_schedule_t *ks, unsigned char S[16],
     unsigned char *m, const unsigned char *c, size_t mlen)
{
    /* Nothing to do if the message is empty */
    if (!mlen)
        return;

    /* Process all block except the last */
    romulus_set_domain(ks, 0x24);
    while (mlen > 16) {
        skinny_plus_encrypt(ks, S, S);
        romulus_rho_inverse(S, m, c);
        romulus_update_counter(ks->TK1);
        c += 16;
        m += 16;
        mlen -= 16;
    }

    /* Handle the last block */
    skinny_plus_encrypt(ks, S, S);
    romulus_rho_inverse_short(S, m, c, (unsigned)mlen);
}

int romulus_m_aead_encrypt
    (unsigned char *c, size_t *clen,
     const unsigned char *m, size_t mlen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    skinny_plus_key_schedule_t ks;
    unsigned char S[16];

    /* Set the length of the returned ciphertext */
    *clen = mlen + ROMULUS_M_TAG_SIZE;

    /* Process the associated data and the plaintext message */
    memset(S, 0, sizeof(S));
    romulus_m_process_ad(&ks, S, k, npub, ad, adlen, m, mlen);

    /* Generate the authentication tag, which is also the initialization
     * vector for the encryption portion of the packet processing */
    romulus_generate_tag(S, S);
    memcpy(c + mlen, S, ROMULUS_M_TAG_SIZE);

    /* Re-initialize the key schedule with the key and nonce */
    romulus_schedule_init(&ks, k, npub);

    /* Encrypt the plaintext to produce the ciphertext */
    romulus_m_encrypt(&ks, S, c, m, mlen);
    return 0;
}

int romulus_m_aead_decrypt
    (unsigned char *m, size_t *mlen,
     const unsigned char *c, size_t clen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    skinny_plus_key_schedule_t ks;
    unsigned char S[16];

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < ROMULUS_M_TAG_SIZE)
        return -1;
    *mlen = clen - ROMULUS_M_TAG_SIZE;

    /* Initialize the key schedule with the key and nonce */
    romulus_schedule_init(&ks, k, npub);

    /* Decrypt the ciphertext to produce the plaintext, using the
     * authentication tag as the initialization vector for decryption */
    clen -= ROMULUS_M_TAG_SIZE;
    memcpy(S, c + clen, ROMULUS_M_TAG_SIZE);
    romulus_m_decrypt(&ks, S, m, c, clen);

    /* Process the associated data */
    memset(S, 0, sizeof(S));
    romulus_m_process_ad(&ks, S, k, npub, ad, adlen, m, clen);

    /* Check the authentication tag */
    romulus_generate_tag(S, S);
    return aead_check_tag(m, clen, S, c + clen, ROMULUS_M_TAG_SIZE);
}
