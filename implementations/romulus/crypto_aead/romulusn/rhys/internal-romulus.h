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

#ifndef LW_INTERNAL_ROMULUS_H
#define LW_INTERNAL_ROMULUS_H

#include "internal-skinny-plus.h"

/**
 * \file internal-romulus.h
 * \brief Common functions for Romulus AEAD modes.
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Sets the domain separation value for Romulus-N, M, and T.
 *
 * \param ks The key schedule to set the domain separation value into.
 * \param domain The domain separation value.
 */
#define romulus_set_domain(ks, domain) ((ks)->TK1[7] = (domain))

/**
 * \brief Updates the 56-bit LFSR block counter for Romulus-N, M, and T.
 *
 * \param TK1 Points to the TK1 part of the key schedule containing the LFSR.
 */
void romulus_update_counter(uint8_t TK1[16]);

/**
 * \brief Initializes the key schedule for Romulus-N, M, or T.
 *
 * \param ks Points to the key schedule to initialize.
 * \param k Points to the 16 bytes of the key.
 * \param npub Points to the 16 bytes of the nonce.
 */
void romulus_schedule_init
    (skinny_plus_key_schedule_t *ks,
     const unsigned char *k, const unsigned char *npub);

/**
 * \brief Applies the Romulus rho function.
 *
 * \param S The rolling Romulus state.
 * \param C Ciphertext message output block.
 * \param M Plaintext message input block.
 */
void romulus_rho
    (unsigned char S[16], unsigned char C[16], const unsigned char M[16]);

/**
 * \brief Applies the inverse of the Romulus rho function.
 *
 * \param S The rolling Romulus state.
 * \param M Plaintext message output block.
 * \param C Ciphertext message input block.
 */
void romulus_rho_inverse
    (unsigned char S[16], unsigned char M[16], const unsigned char C[16]);

/**
 * \brief Applies the Romulus rho function to a short block.
 *
 * \param S The rolling Romulus state.
 * \param C Ciphertext message output block.
 * \param M Plaintext message input block.
 * \param len Length of the short block, must be less than 16.
 */
void romulus_rho_short
    (unsigned char S[16], unsigned char C[16],
     const unsigned char M[16], unsigned len);

/**
 * \brief Applies the inverse of the Romulus rho function to a short block.
 *
 * \param S The rolling Romulus state.
 * \param M Plaintext message output block.
 * \param C Ciphertext message input block.
 * \param len Length of the short block, must be less than 16.
 */
void romulus_rho_inverse_short
    (unsigned char S[16], unsigned char M[16],
     const unsigned char C[16], unsigned len);

/**
 * \brief Generates the authentication tag from the rolling Romulus state.
 *
 * \param T Buffer to receive the generated tag; can be the same as S.
 * \param S The rolling Romulus state.
 */
void romulus_generate_tag(unsigned char T[16], const unsigned char S[16]);

#ifdef __cplusplus
}
#endif

#endif
