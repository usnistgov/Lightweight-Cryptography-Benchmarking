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

#ifndef LW_INTERNAL_SKINNY_PLUS_H
#define LW_INTERNAL_SKINNY_PLUS_H

/**
 * \file internal-skinny-plus.h
 * \brief SKINNY-128-384+ block cipher.
 *
 * References: https://eprint.iacr.org/2016/660.pdf,
 * https://romulusae.github.io/romulus/
 */

#include <stddef.h>
#include <stdint.h>
#include "internal-skinny-plus-config.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Size of a block for SKINNY-128-384+.
 */
#define SKINNY_PLUS_BLOCK_SIZE 16

/**
 * \brief Number of rounds for SKINNY-128-384+.
 */
#define SKINNY_PLUS_ROUNDS 40

/**
 * \brief Structure of the key schedule for SKINNY-128-384+.
 */
typedef struct
{
    /** TK1 for the tweakable part of the key schedule */
    uint8_t TK1[16];

#if SKINNY_PLUS_VARIANT == SKINNY_PLUS_VARIANT_TINY
    /** TK2 for the tiny key schedule */
    uint8_t TK2[16];

    /** TK3 for the tiny key schedule */
    uint8_t TK3[16];
#elif SKINNY_PLUS_VARIANT == SKINNY_PLUS_VARIANT_FULL
    /** Words of the full key schedule */
    uint32_t k[SKINNY_PLUS_ROUNDS * 4];
#else
    /** Words of the small key schedule */
    uint32_t k[SKINNY_PLUS_ROUNDS * 2];
#endif

} skinny_plus_key_schedule_t;

/**
 * \brief Initializes the key schedule for SKINNY-128-384+.
 *
 * \param ks Points to the key schedule to initialize.
 * \param key Points to the key data.
 */
void skinny_plus_init
    (skinny_plus_key_schedule_t *ks, const unsigned char key[48]);

/**
 * \brief Initializes the key schedule for SKINNY-128-384+ without TK1.
 *
 * \param ks Points to the key schedule to initialize.
 * \param tk2 Points to the 16 bytes of key data for TK2.
 * \param tk3 Points to the 16 bytes of key data for TK3.
 */
void skinny_plus_init_without_tk1
    (skinny_plus_key_schedule_t *ks, const unsigned char *tk2,
     const unsigned char *tk3);

/**
 * \brief Encrypts a 128-bit block with SKINNY-128-384+.
 *
 * \param ks Points to the SKINNY-128-384+ key schedule.
 * \param output Output buffer which must be at least 16 bytes in length.
 * \param input Input buffer which must be at least 16 bytes in length.
 *
 * The \a input and \a output buffers can be the same buffer for
 * in-place encryption.
 */
void skinny_plus_encrypt
    (const skinny_plus_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input);

/**
 * \brief Decrypts a 128-bit block with SKINNY-128-384+.
 *
 * \param ks Points to the SKINNY-128-384+ key schedule.
 * \param output Output buffer which must be at least 16 bytes in length.
 * \param input Input buffer which must be at least 16 bytes in length.
 *
 * The \a input and \a output buffers can be the same buffer for
 * in-place decryption.
 */
void skinny_plus_decrypt
    (const skinny_plus_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input);

/**
 * \brief Encrypts a 128-bit block with SKINNY-128-384+ and a
 * fully specified tweakey value.
 *
 * \param key Points to the 384-bit tweakey value.
 * \param output Output buffer which must be at least 16 bytes in length.
 * \param input Input buffer which must be at least 16 bytes in length.
 *
 * The \a input and \a output buffers can be the same buffer for
 * in-place encryption.
 *
 * This version is useful when the entire tweakey changes from block to
 * block.  It is slower than the other versions of SKINNY-128-384+ but
 * more memory-efficient.
 */
void skinny_plus_encrypt_tk_full
    (const unsigned char key[48], unsigned char *output,
     const unsigned char *input);

/**
 * \brief Decrypts a 128-bit block with SKINNY-128-384+ and a
 * fully specified tweakey value.
 *
 * \param key Points to the 384-bit tweakey value.
 * \param output Output buffer which must be at least 16 bytes in length.
 * \param input Input buffer which must be at least 16 bytes in length.
 *
 * The \a input and \a output buffers can be the same buffer for
 * in-place decryption.
 *
 * This version is useful when the entire tweakey changes from block to
 * block.  It is slower than the other versions of SKINNY-128-384+ but
 * more memory-efficient.
 */
void skinny_plus_decrypt_tk_full
    (const unsigned char key[48], unsigned char *output,
     const unsigned char *input);

#ifdef __cplusplus
}
#endif

#endif
