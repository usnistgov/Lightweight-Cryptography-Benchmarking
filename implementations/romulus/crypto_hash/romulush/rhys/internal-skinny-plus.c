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

#include "internal-skinny-plus.h"
#include "internal-util.h"
#include <string.h>
#include <stdio.h>

#if !SKINNY_PLUS_VARIANT_ASM

#if SKINNY_PLUS_VARIANT == SKINNY_PLUS_VARIANT_FULL

/**
 * \brief Round constants for SKINNY-128-384+ in fixsliced form.
 *
 * Some of the constants are inverted to help avoid some of the NOT
 * operations in the S-box computations later.
 */
static uint32_t const skinny_fixsliced_rc[SKINNY_PLUS_ROUNDS * 4] = {
    0x00000004U, 0xFFFFFFBFU, 0x00000000U, 0x00000000U, 0x00000000U,
    0x00000000U, 0x10000100U, 0xFFFFFEFFU, 0x44000000U, 0xFBFFFFFFU,
    0x00000000U, 0x04000000U, 0x00100000U, 0x00100000U, 0x00100001U,
    0xFFEFFFFFU, 0x00440000U, 0xFFAFFFFFU, 0x00400000U, 0x00400000U,
    0x01000000U, 0x01000000U, 0x01401000U, 0xFFBFFFFFU, 0x01004000U,
    0xFEFFFBFFU, 0x00000400U, 0x00000400U, 0x00000010U, 0x00000000U,
    0x00010410U, 0xFFFFFBEFU, 0x00000054U, 0xFFFFFFAFU, 0x00000000U,
    0x00000040U, 0x00000100U, 0x00000100U, 0x10000140U, 0xFFFFFEFFU,
    0x44000000U, 0xFFFFFEFFU, 0x04000000U, 0x04000000U, 0x00100000U,
    0x00100000U, 0x04000001U, 0xFBFFFFFFU, 0x00140000U, 0xFFAFFFFFU,
    0x00400000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x01401000U,
    0xFEBFFFFFU, 0x01004400U, 0xFFFFFBFFU, 0x00000000U, 0x00000400U,
    0x00000010U, 0x00000010U, 0x00010010U, 0xFFFFFFFFU, 0x00000004U,
    0xFFFFFFAFU, 0x00000040U, 0x00000040U, 0x00000100U, 0x00000000U,
    0x10000140U, 0xFFFFFFBFU, 0x40000100U, 0xFBFFFEFFU, 0x00000000U,
    0x04000000U, 0x00100000U, 0x00000000U, 0x04100001U, 0xFFEFFFFFU,
    0x00440000U, 0xFFEFFFFFU, 0x00000000U, 0x00400000U, 0x01000000U,
    0x01000000U, 0x00401000U, 0xFFFFFFFFU, 0x00004000U, 0xFEFFFFFFU,
    0x00000400U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00010400U,
    0xFFFFFBFFU, 0x00000014U, 0xFFFFFFBFU, 0x00000000U, 0x00000000U,
    0x00000000U, 0x00000000U, 0x10000100U, 0xFFFFFFFFU, 0x40000000U,
    0xFBFFFFFFU, 0x00000000U, 0x04000000U, 0x00100000U, 0x00000000U,
    0x00100001U, 0xFFEFFFFFU, 0x00440000U, 0xFFAFFFFFU, 0x00000000U,
    0x00400000U, 0x01000000U, 0x01000000U, 0x01401000U, 0xFFFFFFFFU,
    0x00004000U, 0xFEFFFFFFU, 0x00000400U, 0x00000400U, 0x00000010U,
    0x00000000U, 0x00010400U, 0xFFFFFBFFU, 0x00000014U, 0xFFFFFFAFU,
    0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x10000140U,
    0xFFFFFEFFU, 0x44000000U, 0xFFFFFFFFU, 0x00000000U, 0x04000000U,
    0x00100000U, 0x00100000U, 0x00000001U, 0xFFEFFFFFU, 0x00440000U,
    0xFFAFFFFFU, 0x00400000U, 0x00000000U, 0x00000000U, 0x01000000U,
    0x01401000U, 0xFFBFFFFFU, 0x01004000U, 0xFFFFFBFFU, 0x00000400U,
    0x00000400U, 0x00000010U, 0x00000000U, 0x00010010U, 0xFFFFFBFFU
};

/**
 * \brief Swaps bits within two words.
 *
 * \param a The first word.
 * \param b The second word.
 * \param mask Mask for the bits to shift.
 * \param shift Shift amount in bits.
 */
#define skinny_swap_move(a, b, mask, shift) \
    do { \
        uint32_t tmp = ((b) ^ ((a) >> (shift))) & (mask); \
        (b) ^= tmp; \
        (a) ^= tmp << (shift); \
    } while (0)

/**
 * \brief Converts a 16-byte input buffer into fixsliced form.
 *
 * \param a Reference to the first 32-bit word of the fixsliced form.
 * \param b Reference to the second 32-bit word of the fixsliced form.
 * \param c Reference to the third 32-bit word of the fixsliced form.
 * \param d Reference to the fourth 32-bit word of the fixsliced form.
 * \param in Points to the 16-byte input buffer.
 */
#define skinny_to_fixsliced(a, b, c, d, in) \
    do { \
        (a) = le_load_word32((in)); \
        (c) = le_load_word32((in) + 4); /* b and c pre-swapped for later */ \
        (b) = le_load_word32((in) + 8); \
        (d) = le_load_word32((in) + 12); \
        skinny_swap_move((a), (a), 0x0A0A0A0AU, 3); \
        skinny_swap_move((b), (b), 0x0A0A0A0AU, 3); \
        skinny_swap_move((c), (c), 0x0A0A0A0AU, 3); \
        skinny_swap_move((d), (d), 0x0A0A0A0AU, 3); \
        skinny_swap_move((c), (a), 0x30303030U, 2); \
        skinny_swap_move((b), (a), 0x0C0C0C0CU, 4); \
        skinny_swap_move((d), (a), 0x03030303U, 6); \
        skinny_swap_move((b), (c), 0x0C0C0C0CU, 2); \
        skinny_swap_move((d), (c), 0x03030303U, 4); \
        skinny_swap_move((d), (b), 0x03030303U, 2); \
    } while (0)

/**
 * \brief Converts a buffer in fixsliced form back into bytes.
 *
 * \param out Points to the 16-byte output buffer.
 * \param a Reference to the first 32-bit word of the fixsliced form.
 * \param b Reference to the second 32-bit word of the fixsliced form.
 * \param c Reference to the third 32-bit word of the fixsliced form.
 * \param d Reference to the fourth 32-bit word of the fixsliced form.
 *
 * \note This macro will destroy the contents of a, b, c, and d.
 */
#define skinny_from_fixsliced(out, a, b, c, d) \
    do { \
        skinny_swap_move((d), (b), 0x03030303U, 2); \
        skinny_swap_move((d), (c), 0x03030303U, 4); \
        skinny_swap_move((b), (c), 0x0C0C0C0CU, 2); \
        skinny_swap_move((d), (a), 0x03030303U, 6); \
        skinny_swap_move((b), (a), 0x0C0C0C0CU, 4); \
        skinny_swap_move((c), (a), 0x30303030U, 2); \
        skinny_swap_move((a), (a), 0x0A0A0A0AU, 3); \
        skinny_swap_move((b), (b), 0x0A0A0A0AU, 3); \
        skinny_swap_move((c), (c), 0x0A0A0A0AU, 3); \
        skinny_swap_move((d), (d), 0x0A0A0A0AU, 3); \
        le_store_word32((out), (a)); \
        le_store_word32((out) + 4, (c)); /* undo pre-swapping of b and c */ \
        le_store_word32((out) + 8, (b)); \
        le_store_word32((out) + 12, (d)); \
    } while (0)

/**
 * \brief Applies the first S-box to the fix-sliced state.
 *
 * \param s0 First 32-bit word of the state.
 * \param s1 Second 32-bit word of the state.
 * \param s2 Third 32-bit word of the state.
 * \param s3 Fourth 32-bit word of the state.
 */
#define skinny_fixsliced_sbox_1(s0, s1, s2, s3) \
    do { \
        (s3) ^= ~((s0) | (s1)); \
        skinny_swap_move((s2), (s1), 0x55555555U, 1); \
        skinny_swap_move((s3), (s2), 0x55555555U, 1); \
        (s1) ^= ~((s2) | (s3)); \
        skinny_swap_move((s1), (s0), 0x55555555U, 1); \
        skinny_swap_move((s0), (s3), 0x55555555U, 1); \
        (s3) ^= ~((s0) | (s1)); \
        skinny_swap_move((s2), (s1), 0x55555555U, 1); \
        skinny_swap_move((s3), (s2), 0x55555555U, 1); \
        (s1) ^= ((s2) | (s3)); \
        skinny_swap_move((s3), (s0), 0x55555555U, 0); \
    } while (0)

/**
 * \brief Applies the inverse of the first S-box to the fix-sliced state.
 *
 * \param s0 First 32-bit word of the state.
 * \param s1 Second 32-bit word of the state.
 * \param s2 Third 32-bit word of the state.
 * \param s3 Fourth 32-bit word of the state.
 */
#define skinny_inv_fixsliced_sbox_1(s0, s1, s2, s3) \
    do { \
        skinny_swap_move((s3), (s0), 0x55555555U, 0); \
        (s1) ^= ((s2) | (s3)); \
        skinny_swap_move((s3), (s2), 0x55555555U, 1); \
        skinny_swap_move((s2), (s1), 0x55555555U, 1); \
        (s3) ^= ~((s0) | (s1)); \
        skinny_swap_move((s0), (s3), 0x55555555U, 1); \
        skinny_swap_move((s1), (s0), 0x55555555U, 1); \
        (s1) ^= ~((s2) | (s3)); \
        skinny_swap_move((s3), (s2), 0x55555555U, 1); \
        skinny_swap_move((s2), (s1), 0x55555555U, 1); \
        (s3) ^= ~((s0) | (s1)); \
    } while (0)

/**
 * \brief Applies the second S-box to the fix-sliced state.
 *
 * \param s0 First 32-bit word of the state.
 * \param s1 Second 32-bit word of the state.
 * \param s2 Third 32-bit word of the state.
 * \param s3 Fourth 32-bit word of the state.
 */
#define skinny_fixsliced_sbox_2(s0, s1, s2, s3) \
    do { \
        (s1) ^= ~((s2) | (s3)); \
        skinny_swap_move((s1), (s0), 0x55555555U, 1); \
        skinny_swap_move((s0), (s3), 0x55555555U, 1); \
        (s3) ^= ~((s0) | (s1)); \
        skinny_swap_move((s2), (s1), 0x55555555U, 1); \
        skinny_swap_move((s3), (s2), 0x55555555U, 1); \
        (s1) ^= ~((s2) | (s3)); \
        skinny_swap_move((s1), (s0), 0x55555555U, 1); \
        skinny_swap_move((s0), (s3), 0x55555555U, 1); \
        (s3) ^= ((s0) | (s1)); \
        skinny_swap_move((s1), (s2), 0x55555555U, 0); \
    } while (0)

/**
 * \brief Applies the inverse of the second S-box to the fix-sliced state.
 *
 * \param s0 First 32-bit word of the state.
 * \param s1 Second 32-bit word of the state.
 * \param s2 Third 32-bit word of the state.
 * \param s3 Fourth 32-bit word of the state.
 */
#define skinny_inv_fixsliced_sbox_2(s0, s1, s2, s3) \
    do { \
        skinny_swap_move((s1), (s2), 0x55555555U, 0); \
        (s3) ^= ((s0) | (s1)); \
        skinny_swap_move((s0), (s3), 0x55555555U, 1); \
        skinny_swap_move((s1), (s0), 0x55555555U, 1); \
        (s1) ^= ~((s2) | (s3)); \
        skinny_swap_move((s3), (s2), 0x55555555U, 1); \
        skinny_swap_move((s2), (s1), 0x55555555U, 1); \
        (s3) ^= ~((s0) | (s1)); \
        skinny_swap_move((s0), (s3), 0x55555555U, 1); \
        skinny_swap_move((s1), (s0), 0x55555555U, 1); \
        (s1) ^= ~((s2) | (s3)); \
    } while (0)

/**
 * \brief Mixes the columns for the first round of 4 in the fix-sliced state.
 *
 * \param s State word to be mixed.
 */
#define skinny_mix_columns_1_of_4(s) \
    do { \
        uint32_t t = rightRotate24((s)) & 0x0C0C0C0CU; \
        (s) ^= rightRotate30(t); \
        t = rightRotate16((s)) & 0xC0C0C0C0U; \
        (s) ^= rightRotate4(t); \
        t = rightRotate8((s)) & 0x0C0C0C0CU; \
        (s) ^= rightRotate2(t); \
    } while (0)

/**
 * \brief Inverse mix of the columns for the first round of 4 in
 * the fix-sliced state.
 *
 * \param s State word to be mixed.
 */
#define skinny_inv_mix_columns_1_of_4(s) \
    do { \
        uint32_t t = rightRotate8((s)) & 0x0C0C0C0CU; \
        (s) ^= rightRotate2(t); \
        t = rightRotate16((s)) & 0xC0C0C0C0U; \
        (s) ^= rightRotate4(t); \
        t = rightRotate24((s)) & 0x0C0C0C0CU; \
        (s) ^= rightRotate30(t); \
    } while (0)

/**
 * \brief Mixes the columns for the second round of 4 in the fix-sliced state.
 *
 * \param s State word to be mixed.
 */
#define skinny_mix_columns_2_of_4(s) \
    do { \
        uint32_t t = rightRotate16((s)) & 0x30303030U; \
        (s) ^= rightRotate30(t); \
        t = (s) & 0x03030303U; \
        (s) ^= rightRotate28(t); \
        t = rightRotate16((s)) & 0x30303030U; \
        (s) ^= rightRotate2(t); \
    } while (0)

/**
 * \brief Inverse mix of the columns for the second round of 4
 * in the fix-sliced state.
 *
 * \param s State word to be mixed.
 */
#define skinny_inv_mix_columns_2_of_4(s) \
    do { \
        uint32_t t = rightRotate16((s)) & 0x30303030U; \
        (s) ^= rightRotate2(t); \
        t = (s) & 0x03030303U; \
        (s) ^= rightRotate28(t); \
        t = rightRotate16((s)) & 0x30303030U; \
        (s) ^= rightRotate30(t); \
    } while (0)

/**
 * \brief Mixes the columns for the third round of 4 in the fix-sliced state.
 *
 * \param s State word to be mixed.
 */
#define skinny_mix_columns_3_of_4(s) \
    do { \
        uint32_t t = rightRotate8((s)) & 0xC0C0C0C0U; \
        (s) ^= rightRotate6(t); \
        t = rightRotate16((s)) & 0x0C0C0C0CU; \
        (s) ^= rightRotate28(t); \
        t = rightRotate24((s)) & 0xC0C0C0C0U; \
        (s) ^= rightRotate2(t); \
    } while (0)

/**
 * \brief Inverse mix of the columns for the third round of 4
 * in the fix-sliced state.
 *
 * \param s State word to be mixed.
 */
#define skinny_inv_mix_columns_3_of_4(s) \
    do { \
        uint32_t t = rightRotate24((s)) & 0xC0C0C0C0U; \
        (s) ^= rightRotate2(t); \
        t = rightRotate16((s)) & 0x0C0C0C0CU; \
        (s) ^= rightRotate28(t); \
        t = rightRotate8((s)) & 0xC0C0C0C0U; \
        (s) ^= rightRotate6(t); \
    } while (0)

/**
 * \brief Mixes the columns for the fourth round of 4 in the fix-sliced state.
 *
 * \param s State word to be mixed.
 */
#define skinny_mix_columns_4_of_4(s) \
    do { \
        uint32_t t = (s) & 0x03030303U; \
        (s) ^= rightRotate30(t); \
        t = (s) & 0x30303030U; \
        (s) ^= rightRotate4(t); \
        t = (s) & 0x03030303U; \
        (s) ^= rightRotate26(t); \
    } while (0)

/**
 * \brief Inverse mix of the columns for the fourth round of 4
 * in the fix-sliced state.
 *
 * \param s State word to be mixed.
 */
#define skinny_inv_mix_columns_4_of_4(s) \
    do { \
        uint32_t t = (s) & 0x03030303U; \
        (s) ^= rightRotate26(t); \
        t = (s) & 0x30303030U; \
        (s) ^= rightRotate4(t); \
        t = (s) & 0x03030303U; \
        (s) ^= rightRotate30(t); \
    } while (0)

/**
 * \brief Performs four fixsliced encryption rounds using 16 round keys.
 *
 * \param s0 First 32-bit word of the state to encrypt.
 * \param s1 Second 32-bit word of the state to encrypt.
 * \param s2 Third 32-bit word of the state to encrypt.
 * \param s3 Fourth 32-bit word of the state to encrypt.
 * \param tk1 Points to the 16 round keys for the TK1 part of the schedule.
 * \param tk23 Points to the 16 round keys for the TK2/3 part of the schedule.
 */
#define skinny_encrypt_4_rounds(s0, s1, s2, s3, tk1, tk23) \
    do { \
        /* Apply the S-box for the first round */ \
        skinny_fixsliced_sbox_1((s0), (s1), (s2), (s3)); \
        \
        /* XOR with the key schedule for the first round */ \
        (s0) ^= (tk1)[0] ^ (tk23)[0]; \
        (s1) ^= (tk1)[1] ^ (tk23)[1]; \
        (s2) ^= (tk1)[2] ^ (tk23)[2]; \
        (s3) ^= (tk1)[3] ^ (tk23)[3]; \
        \
        /* Mix the columns for the first round */ \
        skinny_mix_columns_1_of_4((s0)); \
        skinny_mix_columns_1_of_4((s1)); \
        skinny_mix_columns_1_of_4((s2)); \
        skinny_mix_columns_1_of_4((s3)); \
        \
        /* Apply the S-box for the second round */ \
        skinny_fixsliced_sbox_2((s0), (s1), (s2), (s3)); \
        \
        /* XOR with the key schedule for the second round */ \
        (s0) ^= (tk1)[4] ^ (tk23)[4]; \
        (s1) ^= (tk1)[5] ^ (tk23)[5]; \
        (s2) ^= (tk1)[6] ^ (tk23)[6]; \
        (s3) ^= (tk1)[7] ^ (tk23)[7]; \
        \
        /* Mix the columns for the second round */ \
        skinny_mix_columns_2_of_4((s0)); \
        skinny_mix_columns_2_of_4((s1)); \
        skinny_mix_columns_2_of_4((s2)); \
        skinny_mix_columns_2_of_4((s3)); \
        \
        /* Apply the S-box for the third round */ \
        skinny_fixsliced_sbox_1((s0), (s1), (s2), (s3)); \
        \
        /* XOR with the key schedule for the third round */ \
        (s0) ^= (tk1)[8]  ^ (tk23)[8]; \
        (s1) ^= (tk1)[9]  ^ (tk23)[9]; \
        (s2) ^= (tk1)[10] ^ (tk23)[10]; \
        (s3) ^= (tk1)[11] ^ (tk23)[11]; \
        \
        /* Mix the columns for the third round */ \
        skinny_mix_columns_3_of_4((s0)); \
        skinny_mix_columns_3_of_4((s1)); \
        skinny_mix_columns_3_of_4((s2)); \
        skinny_mix_columns_3_of_4((s3)); \
        \
        /* Apply the S-box for the fourth round */ \
        skinny_fixsliced_sbox_2((s0), (s1), (s2), (s3)); \
        \
        /* XOR with the key schedule for the fourth round */ \
        (s0) ^= (tk1)[12] ^ (tk23)[12]; \
        (s1) ^= (tk1)[13] ^ (tk23)[13]; \
        (s2) ^= (tk1)[14] ^ (tk23)[14]; \
        (s3) ^= (tk1)[15] ^ (tk23)[15]; \
        \
        /* Mix the columns for the fourth round */ \
        skinny_mix_columns_4_of_4((s0)); \
        skinny_mix_columns_4_of_4((s1)); \
        skinny_mix_columns_4_of_4((s2)); \
        skinny_mix_columns_4_of_4((s3)); \
    } while (0)

/**
 * \brief Performs four fixsliced decryption rounds using 16 round keys.
 *
 * \param s0 First 32-bit word of the state to decrypt.
 * \param s1 Second 32-bit word of the state to decrypt.
 * \param s2 Third 32-bit word of the state to decrypt.
 * \param s3 Fourth 32-bit word of the state to decrypt.
 * \param tk1 Points to the 16 round keys for the TK1 part of the schedule.
 * \param tk23 Points to the 16 round keys for the TK2/3 part of the schedule.
 */
#define skinny_decrypt_4_rounds(s0, s1, s2, s3, tk1, tk23) \
    do { \
        /* Inverse mix of the columns for the fourth round */ \
        skinny_inv_mix_columns_4_of_4((s0)); \
        skinny_inv_mix_columns_4_of_4((s1)); \
        skinny_inv_mix_columns_4_of_4((s2)); \
        skinny_inv_mix_columns_4_of_4((s3)); \
        \
        /* XOR with the key schedule for the fourth round */ \
        (s0) ^= (tk1)[12] ^ (tk23)[12]; \
        (s1) ^= (tk1)[13] ^ (tk23)[13]; \
        (s2) ^= (tk1)[14] ^ (tk23)[14]; \
        (s3) ^= (tk1)[15] ^ (tk23)[15]; \
        \
        /* Apply the inverse of the S-box for the fourth round */ \
        skinny_inv_fixsliced_sbox_2((s0), (s1), (s2), (s3)); \
        \
        /* Inverse mix of the columns for the third round */ \
        skinny_inv_mix_columns_3_of_4((s0)); \
        skinny_inv_mix_columns_3_of_4((s1)); \
        skinny_inv_mix_columns_3_of_4((s2)); \
        skinny_inv_mix_columns_3_of_4((s3)); \
        \
        /* XOR with the key schedule for the third round */ \
        (s0) ^= (tk1)[8]  ^ (tk23)[8]; \
        (s1) ^= (tk1)[9]  ^ (tk23)[9]; \
        (s2) ^= (tk1)[10] ^ (tk23)[10]; \
        (s3) ^= (tk1)[11] ^ (tk23)[11]; \
        \
        /* Apply the inverse of the S-box for the third round */ \
        skinny_inv_fixsliced_sbox_1((s0), (s1), (s2), (s3)); \
        \
        /* Inverse mix of the columns for the second round */ \
        skinny_inv_mix_columns_2_of_4((s0)); \
        skinny_inv_mix_columns_2_of_4((s1)); \
        skinny_inv_mix_columns_2_of_4((s2)); \
        skinny_inv_mix_columns_2_of_4((s3)); \
        \
        /* XOR with the key schedule for the second round */ \
        (s0) ^= (tk1)[4] ^ (tk23)[4]; \
        (s1) ^= (tk1)[5] ^ (tk23)[5]; \
        (s2) ^= (tk1)[6] ^ (tk23)[6]; \
        (s3) ^= (tk1)[7] ^ (tk23)[7]; \
        \
        /* Apply the inverse of the S-box for the second round */ \
        skinny_inv_fixsliced_sbox_2((s0), (s1), (s2), (s3)); \
        \
        /* Inverse mix of the columns for the first round */ \
        skinny_inv_mix_columns_1_of_4((s0)); \
        skinny_inv_mix_columns_1_of_4((s1)); \
        skinny_inv_mix_columns_1_of_4((s2)); \
        skinny_inv_mix_columns_1_of_4((s3)); \
        \
        /* XOR with the key schedule for the first round */ \
        (s0) ^= (tk1)[0] ^ (tk23)[0]; \
        (s1) ^= (tk1)[1] ^ (tk23)[1]; \
        (s2) ^= (tk1)[2] ^ (tk23)[2]; \
        (s3) ^= (tk1)[3] ^ (tk23)[3]; \
        \
        /* Apply the inverse of the S-box for the first round */ \
        skinny_inv_fixsliced_sbox_1((s0), (s1), (s2), (s3)); \
    } while (0)

/**
 * \brief Permutes a TK value and expands it to multiple rounds of data.
 *
 * \param k Points to the output key schedule generated from the TK value.
 * \param s0 First 32-bit word of the TK value.
 * \param s1 Second 32-bit word of the TK value.
 * \param s2 Third 32-bit word of the TK value.
 * \param s3 Fourth 32-bit word of the TK value.
 * \param rounds Number of rounds to expand, with 4 output words per round;
 * must be a multiple of 16.
 *
 * When expanding TK1, s0...s3 contains the fixsliced version of TK1 on entry
 * and k should point to an array of all zeroes.
 *
 * When expanding TK2 and TK3, s0...s3 should be zero, and k should point
 * to an array containing the LFSR-expanded versions of TK2 and TK3.
 */
static void skinny_permute_and_expand_tk
    (uint32_t *k, uint32_t s0, uint32_t s1, uint32_t s2,
     uint32_t s3, unsigned rounds)
{
    uint32_t t0, t1, t2, t3;
    unsigned round;
    int phase = 1;

    /* Generate key schedule words in groups of 8 rounds */
    t0 = k[0] ^ s0;
    t1 = k[1] ^ s1;
    t2 = k[2] ^ s2;
    t3 = k[3] ^ s3;
    for (round = 0; round < rounds; round += 8, phase = !phase, k += 32) {
        /* Rounds 1 and 9 */
        k[0] = t2 & 0xF0F0F0F0U;
        k[1] = t3 & 0xF0F0F0F0U;
        k[2] = t0 & 0xF0F0F0F0U;
        k[3] = t1 & 0xF0F0F0F0U;
        t0 = k[4] ^ s0;
        t1 = k[5] ^ s1;
        t2 = k[6] ^ s2;
        t3 = k[7] ^ s3;

        /* Rounds 2 and 10 */
        if (phase) {
            /* P^2 */
            #define skinny_permute_tk_2(t) \
                ((rightRotate14((t)) & 0xCC00CC00U) | \
                 (((t) & 0x000000FFU) << 16) | \
                 (((t) & 0xCC000000U) >> 2)  | \
                 (((t) & 0x0033CC00U) >> 8)  | \
                 (((t) & 0x00CC0000U) >> 18))
            t0 = skinny_permute_tk_2(t0);
            t1 = skinny_permute_tk_2(t1);
            t2 = skinny_permute_tk_2(t2);
            t3 = skinny_permute_tk_2(t3);
        } else {
            /* P^10 */
            #define skinny_permute_tk_10(t) \
                ((rightRotate8((t))  & 0xCC330000U) | \
                 (rightRotate26((t)) & 0x33000033U) | \
                 (rightRotate22((t)) & 0x00CCCC00U) | \
                 (((t) & 0x00330000U) >> 14) | \
                 (((t) & 0x0000CC00U) >> 2))
            t0 = skinny_permute_tk_10(t0);
            t1 = skinny_permute_tk_10(t1);
            t2 = skinny_permute_tk_10(t2);
            t3 = skinny_permute_tk_10(t3);
        }
        k[4] = rightRotate26(t0) & 0xC3C3C3C3U;
        k[5] = rightRotate26(t1) & 0xC3C3C3C3U;
        k[6] = rightRotate26(t2) & 0xC3C3C3C3U;
        k[7] = rightRotate26(t3) & 0xC3C3C3C3U;

        /* Rounds 3 and 11 */
        k[8]  = (rightRotate28(t2) & 0x03030303U) |
                (rightRotate12(t2) & 0x0C0C0C0CU);
        k[9]  = (rightRotate28(t3) & 0x03030303U) |
                (rightRotate12(t3) & 0x0C0C0C0CU);
        k[10] = (rightRotate28(t0) & 0x03030303U) |
                (rightRotate12(t0) & 0x0C0C0C0CU);
        k[11] = (rightRotate28(t1) & 0x03030303U) |
                (rightRotate12(t1) & 0x0C0C0C0CU);
        t0 = k[12] ^ s0;
        t1 = k[13] ^ s1;
        t2 = k[14] ^ s2;
        t3 = k[15] ^ s3;

        /* Rounds 4 and 12 */
        if (phase) {
            /* P^4 */
            #define skinny_permute_tk_4(t) \
                ((rightRotate22((t)) & 0xCC0000CCU) | \
                 (rightRotate16((t)) & 0x3300CC00U) | \
                 (rightRotate24((t)) & 0x00CC3300U) | \
                 (((t) & 0x00CC00CCU) >> 2))
            t0 = skinny_permute_tk_4(t0);
            t1 = skinny_permute_tk_4(t1);
            t2 = skinny_permute_tk_4(t2);
            t3 = skinny_permute_tk_4(t3);
        } else {
            /* P^12 */
            #define skinny_permute_tk_12(t) \
                ((rightRotate8((t))  & 0x0000CC33U) | \
                 (rightRotate30((t)) & 0x00CC00CCU) | \
                 (rightRotate10((t)) & 0x33330000U) | \
                 (rightRotate16((t)) & 0xCC003300U))
            t0 = skinny_permute_tk_12(t0);
            t1 = skinny_permute_tk_12(t1);
            t2 = skinny_permute_tk_12(t2);
            t3 = skinny_permute_tk_12(t3);
        }
        k[12] = (rightRotate14(t0) & 0x30303030U) |
                (rightRotate6(t0)  & 0x0C0C0C0CU);
        k[13] = (rightRotate14(t1) & 0x30303030U) |
                (rightRotate6(t1)  & 0x0C0C0C0CU);
        k[14] = (rightRotate14(t2) & 0x30303030U) |
                (rightRotate6(t2)  & 0x0C0C0C0CU);
        k[15] = (rightRotate14(t3) & 0x30303030U) |
                (rightRotate6(t3)  & 0x0C0C0C0CU);

        /* Rounds 5 and 13 */
        k[16] = rightRotate16(t2) & 0xF0F0F0F0U;
        k[17] = rightRotate16(t3) & 0xF0F0F0F0U;
        k[18] = rightRotate16(t0) & 0xF0F0F0F0U;
        k[19] = rightRotate16(t1) & 0xF0F0F0F0U;
        t0 = k[20] ^ s0;
        t1 = k[21] ^ s1;
        t2 = k[22] ^ s2;
        t3 = k[23] ^ s3;

        /* Rounds 6 and 14 */
        if (phase) {
            /* P^6 */
            #define skinny_permute_tk_6(t) \
                ((rightRotate6((t))  & 0xCCCC0000U) | \
                 (rightRotate24((t)) & 0x330000CCU) | \
                 (rightRotate10((t)) & 0x00003333U) | \
                 (((t) & 0x000000CCU) << 14) | \
                 (((t) & 0x00003300U) << 2))
            t0 = skinny_permute_tk_6(t0);
            t1 = skinny_permute_tk_6(t1);
            t2 = skinny_permute_tk_6(t2);
            t3 = skinny_permute_tk_6(t3);
        } else {
            /* P^14 */
            #define skinny_permute_tk_14(t) \
                ((rightRotate24((t)) & 0x0033CC00U) | \
                 (rightRotate14((t)) & 0x00CC0000U) | \
                 (rightRotate30((t)) & 0xCC000000U) | \
                 (rightRotate16((t)) & 0x000000FFU) | \
                 (rightRotate18((t)) & 0x33003300U))
            t0 = skinny_permute_tk_14(t0);
            t1 = skinny_permute_tk_14(t1);
            t2 = skinny_permute_tk_14(t2);
            t3 = skinny_permute_tk_14(t3);
        }
        k[20] = rightRotate10(t0) & 0xC3C3C3C3U;
        k[21] = rightRotate10(t1) & 0xC3C3C3C3U;
        k[22] = rightRotate10(t2) & 0xC3C3C3C3U;
        k[23] = rightRotate10(t3) & 0xC3C3C3C3U;

        /* Rounds 7 and 15 */
        k[24] = (rightRotate12(t2) & 0x03030303U) |
                (rightRotate28(t2) & 0x0C0C0C0CU);
        k[25] = (rightRotate12(t3) & 0x03030303U) |
                (rightRotate28(t3) & 0x0C0C0C0CU);
        k[26] = (rightRotate12(t0) & 0x03030303U) |
                (rightRotate28(t0) & 0x0C0C0C0CU);
        k[27] = (rightRotate12(t1) & 0x03030303U) |
                (rightRotate28(t1) & 0x0C0C0C0CU);
        t0 = k[28] ^ s0;
        t1 = k[29] ^ s1;
        t2 = k[30] ^ s2;
        t3 = k[31] ^ s3;

        /* Rounds 8 and 16 */
        if (phase) {
            /* P^8 */
            #define skinny_permute_tk_8(t) \
                ((rightRotate24((t)) & 0xCC000033U) | \
                 (rightRotate8((t))  & 0x33CC0000U) | \
                 (rightRotate26((t)) & 0x00333300U) | \
                 (((t) & 0x00333300U) >> 6))
            t0 = skinny_permute_tk_8(t0);
            t1 = skinny_permute_tk_8(t1);
            t2 = skinny_permute_tk_8(t2);
            t3 = skinny_permute_tk_8(t3);
        }
        k[28] = (rightRotate30(t0) & 0x30303030U) |
                (rightRotate22(t0) & 0x0C0C0C0CU);
        k[29] = (rightRotate30(t1) & 0x30303030U) |
                (rightRotate22(t1) & 0x0C0C0C0CU);
        k[30] = (rightRotate30(t2) & 0x30303030U) |
                (rightRotate22(t2) & 0x0C0C0C0CU);
        k[31] = (rightRotate30(t3) & 0x30303030U) |
                (rightRotate22(t3) & 0x0C0C0C0CU);
    }
}

/**
 * \brief Initialises the main key schedule from the TK2 and TK3 values.
 *
 * \param keys Output key schedule.
 * \param key_tk2 Points to the 16 byte TK2 value.
 * \param key_tk3 Points to the 16 byte TK3 value.
 */
static void skinny_plus_init_schedule
    (uint32_t *keys, const unsigned char *key_tk2, const unsigned char *key_tk3)
{
    uint32_t tk2_0, tk2_1, tk2_2, tk2_3;
    uint32_t tk3_0, tk3_1, tk3_2, tk3_3;
    uint32_t *k = keys;
    unsigned round;

    /* Run LFSR2 and LFSR3 to generate unpermuted values for all rounds.
     * Every second round is set to zero.  The TK expansion below will
     * fill in the gaps during the next pass. */
    #define LFSR2(tk0, tk1) \
        do { \
            (tk0) ^= ((tk1) & 0xAAAAAAAAU); \
            (tk0) = (((tk0) & 0xAAAAAAAAU) >> 1) | \
                    (((tk0) << 1) & 0xAAAAAAAAU); \
        } while (0)
    #define LFSR3(tk0, tk1) \
        do { \
            (tk0) ^= (((tk1) & 0xAAAAAAAAU) >> 1); \
            (tk0) = (((tk0) & 0xAAAAAAAAU) >> 1) | \
                    (((tk0) << 1) & 0xAAAAAAAAU); \
        } while (0)
    skinny_to_fixsliced(tk2_0, tk2_1, tk2_2, tk2_3, key_tk2);
    skinny_to_fixsliced(tk3_0, tk3_1, tk3_2, tk3_3, key_tk3);
    for (round = 0; round < SKINNY_PLUS_ROUNDS; round += 8, k += 32) {
        /* Round 1 */
        if (round == 0) {
            k[0] = tk2_0 ^ tk3_0;
            k[1] = tk2_1 ^ tk3_1;
            k[2] = tk2_2 ^ tk3_2;
            k[3] = tk2_3 ^ tk3_3;
        } else {
            k[0] = 0;
            k[1] = 0;
            k[2] = 0;
            k[3] = 0;
        }

        /* Round 2 */
        LFSR2(tk2_0, tk2_2);
        LFSR3(tk3_3, tk3_1);
        k[4] = tk2_1 ^ tk3_3;
        k[5] = tk2_2 ^ tk3_0;
        k[6] = tk2_3 ^ tk3_1;
        k[7] = tk2_0 ^ tk3_2;

        /* Round 3 */
        k[8]  = 0;
        k[9]  = 0;
        k[10] = 0;
        k[11] = 0;

        /* Round 4 */
        LFSR2(tk2_1, tk2_3);
        LFSR3(tk3_2, tk3_0);
        k[12] = tk2_2 ^ tk3_2;
        k[13] = tk2_3 ^ tk3_3;
        k[14] = tk2_0 ^ tk3_0;
        k[15] = tk2_1 ^ tk3_1;

        /* Round 5 */
        k[16] = 0;
        k[17] = 0;
        k[18] = 0;
        k[19] = 0;

        /* Round 6 */
        LFSR2(tk2_2, tk2_0);
        LFSR3(tk3_1, tk3_3);
        k[20] = tk2_3 ^ tk3_1;
        k[21] = tk2_0 ^ tk3_2;
        k[22] = tk2_1 ^ tk3_3;
        k[23] = tk2_2 ^ tk3_0;

        /* Round 7 */
        k[24] = 0;
        k[25] = 0;
        k[26] = 0;
        k[27] = 0;

        /* Round 8 */
        LFSR2(tk2_3, tk2_1);
        LFSR3(tk3_0, tk3_2);
        k[28] = tk2_0 ^ tk3_0;
        k[29] = tk2_1 ^ tk3_1;
        k[30] = tk2_2 ^ tk3_2;
        k[31] = tk2_3 ^ tk3_3;
    }

    /* Permute the TK2 and TK3 values for all rounds */
    skinny_permute_and_expand_tk(keys, 0, 0, 0, 0, SKINNY_PLUS_ROUNDS);

    /* Add the round constants to the key schedule */
    for (round = 0; round < (SKINNY_PLUS_ROUNDS * 4); ++round)
        keys[round] ^= skinny_fixsliced_rc[round];
}

void skinny_plus_init
    (skinny_plus_key_schedule_t *ks, const unsigned char key[48])
{
    /* Copy TK1 as-is; it is expanded on the fly during encryption */
    memcpy(ks->TK1, key, 16);

    /* Generate the main key schedule from TK2 and TK3 */
    skinny_plus_init_schedule(ks->k, key + 16, key + 32);
}

void skinny_plus_init_without_tk1
    (skinny_plus_key_schedule_t *ks, const unsigned char *tk2,
     const unsigned char *tk3)
{
    /* Generate the main key schedule from TK2 and TK3 */
    skinny_plus_init_schedule(ks->k, tk2, tk3);
}

void skinny_plus_encrypt
    (const skinny_plus_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input)
{
    uint32_t tk1[16 * 4] = {0};
    uint32_t s0, s1, s2, s3;
    unsigned r;

    /* Convert TK1 into fixsliced form and expand it to 16 rounds.
     * TK1 repeats after 16 rounds, so no need to go further. */
    skinny_to_fixsliced(s0, s1, s2, s3, ks->TK1);
    skinny_permute_and_expand_tk(tk1, s0, s1, s2, s3, 16);

    /* Load the plaintext and convert into fixsliced form */
    skinny_to_fixsliced(s0, s1, s2, s3, input);

    /* Perform the 40 encryption rounds four at a time */
    for (r = 0; r < (SKINNY_PLUS_ROUNDS * 4); r += 16)
        skinny_encrypt_4_rounds(s0, s1, s2, s3, tk1 + (r & 63), ks->k + r);

    /* Convert the ciphertext from fixsliced form and store */
    skinny_from_fixsliced(output, s0, s1, s2, s3);
}

void skinny_plus_decrypt
    (const skinny_plus_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input)
{
    uint32_t tk1[16 * 4] = {0};
    uint32_t s0, s1, s2, s3;
    int r;

    /* Convert TK1 into fixsliced form and expand it to 16 rounds.
     * TK1 repeats after 16 rounds, so no need to go further. */
    skinny_to_fixsliced(s0, s1, s2, s3, ks->TK1);
    skinny_permute_and_expand_tk(tk1, s0, s1, s2, s3, 16);

    /* Load the ciphertext and convert into fixsliced form */
    skinny_to_fixsliced(s0, s1, s2, s3, input);

    /* Perform the 40 decryption rounds four at a time */
    for (r = (SKINNY_PLUS_ROUNDS * 4) - 16; r >= 0; r -= 16)
        skinny_decrypt_4_rounds(s0, s1, s2, s3, tk1 + (r & 63), ks->k + r);

    /* Convert the plaintext from fixsliced form and store */
    skinny_from_fixsliced(output, s0, s1, s2, s3);
}

void skinny_plus_encrypt_tk_full
    (const unsigned char key[48], unsigned char *output,
     const unsigned char *input)
{
    uint32_t tk1[16 * 4] = {0};
    uint32_t k[SKINNY_PLUS_ROUNDS * 4];
    uint32_t s0, s1, s2, s3;
    unsigned r;

    /* Expand the key into a full key schedule */
    skinny_to_fixsliced(s0, s1, s2, s3, key);
    skinny_permute_and_expand_tk(tk1, s0, s1, s2, s3, 16);
    skinny_plus_init_schedule(k, key + 16, key + 32);

    /* Load the plaintext and convert into fixsliced form */
    skinny_to_fixsliced(s0, s1, s2, s3, input);

    /* Perform the 40 encryption rounds four at a time */
    for (r = 0; r < (SKINNY_PLUS_ROUNDS * 4); r += 16)
        skinny_encrypt_4_rounds(s0, s1, s2, s3, tk1 + (r & 63), k + r);

    /* Convert the ciphertext from fixsliced form and store */
    skinny_from_fixsliced(output, s0, s1, s2, s3);
}

void skinny_plus_decrypt_tk_full
    (const unsigned char key[48], unsigned char *output,
     const unsigned char *input)
{
    uint32_t tk1[16 * 4] = {0};
    uint32_t k[SKINNY_PLUS_ROUNDS * 4];
    uint32_t s0, s1, s2, s3;
    int r;

    /* Expand the key into a full key schedule */
    skinny_to_fixsliced(s0, s1, s2, s3, key);
    skinny_permute_and_expand_tk(tk1, s0, s1, s2, s3, 16);
    skinny_plus_init_schedule(k, key + 16, key + 32);

    /* Load the ciphertext and convert into fixsliced form */
    skinny_to_fixsliced(s0, s1, s2, s3, input);

    /* Perform the 40 decryption rounds four at a time */
    for (r = (SKINNY_PLUS_ROUNDS * 4) - 16; r >= 0; r -= 16)
        skinny_decrypt_4_rounds(s0, s1, s2, s3, tk1 + (r & 63), k + r);

    /* Convert the plaintext from fixsliced form and store */
    skinny_from_fixsliced(output, s0, s1, s2, s3);
}

#else /* !SKINNY_PLUS_VARIANT_FULL */

/** @cond skinnyutil */

/* Utilities for implementing SKINNY-128 and its variants */

#define skinny128_LFSR2(x) \
    do { \
        uint32_t _x = (x); \
        (x) = ((_x << 1) & 0xFEFEFEFEU) ^ \
             (((_x >> 7) ^ (_x >> 5)) & 0x01010101U); \
    } while (0)


#define skinny128_LFSR3(x) \
    do { \
        uint32_t _x = (x); \
        (x) = ((_x >> 1) & 0x7F7F7F7FU) ^ \
              (((_x << 7) ^ (_x << 1)) & 0x80808080U); \
    } while (0)

#define skinny128_permute_tk_half(tk2, tk3) \
    do { \
        /* Permute the bottom half of the tweakey state in place, no swap */ \
        uint32_t row2 = tk2; \
        uint32_t row3 = tk3; \
        row3 = (row3 << 16) | (row3 >> 16); \
        tk2 = ((row2 >>  8) & 0x000000FFU) | \
              ((row2 << 16) & 0x00FF0000U) | \
              ( row3        & 0xFF00FF00U); \
        tk3 = ((row2 >> 16) & 0x000000FFU) | \
               (row2        & 0xFF000000U) | \
              ((row3 <<  8) & 0x0000FF00U) | \
              ( row3        & 0x00FF0000U); \
    } while (0)

#define skinny128_inv_permute_tk_half(tk0, tk1) \
    do { \
        /* Permute the top half of the tweakey state in place, no swap */ \
        uint32_t row0 = tk0; \
        uint32_t row1 = tk1; \
        tk0 = ((row0 >> 16) & 0x000000FFU) | \
              ((row0 <<  8) & 0x0000FF00U) | \
              ((row1 << 16) & 0x00FF0000U) | \
              ( row1        & 0xFF000000U); \
        tk1 = ((row0 >> 16) & 0x0000FF00U) | \
              ((row0 << 16) & 0xFF000000U) | \
              ((row1 >> 16) & 0x000000FFU) | \
              ((row1 <<  8) & 0x00FF0000U); \
    } while (0)

/*
 * Apply the SKINNY sbox.  The original version from the specification is
 * equivalent to:
 *
 * #define SBOX_MIX(x)
 *     (((~((((x) >> 1) | (x)) >> 2)) & 0x11111111U) ^ (x))
 * #define SBOX_SWAP(x)
 *     (((x) & 0xF9F9F9F9U) |
 *     (((x) >> 1) & 0x02020202U) |
 *     (((x) << 1) & 0x04040404U))
 * #define SBOX_PERMUTE(x)
 *     ((((x) & 0x01010101U) << 2) |
 *      (((x) & 0x06060606U) << 5) |
 *      (((x) & 0x20202020U) >> 5) |
 *      (((x) & 0xC8C8C8C8U) >> 2) |
 *      (((x) & 0x10101010U) >> 1))
 *
 * x = SBOX_MIX(x);
 * x = SBOX_PERMUTE(x);
 * x = SBOX_MIX(x);
 * x = SBOX_PERMUTE(x);
 * x = SBOX_MIX(x);
 * x = SBOX_PERMUTE(x);
 * x = SBOX_MIX(x);
 * return SBOX_SWAP(x);
 *
 * However, we can mix the bits in their original positions and then
 * delay the SBOX_PERMUTE and SBOX_SWAP steps to be performed with one
 * final permuatation.  This reduces the number of shift operations.
 */
#define skinny128_sbox(x) \
do { \
    uint32_t y; \
    \
    /* Mix the bits */ \
    x = ~x; \
    x ^= (((x >> 2) & (x >> 3)) & 0x11111111U); \
    y  = (((x << 5) & (x << 1)) & 0x20202020U); \
    x ^= (((x << 5) & (x << 4)) & 0x40404040U) ^ y; \
    y  = (((x << 2) & (x << 1)) & 0x80808080U); \
    x ^= (((x >> 2) & (x << 1)) & 0x02020202U) ^ y; \
    y  = (((x >> 5) & (x << 1)) & 0x04040404U); \
    x ^= (((x >> 1) & (x >> 2)) & 0x08080808U) ^ y; \
    x = ~x; \
    \
    /* Permutation generated by http://programming.sirrida.de/calcperm.php */ \
    /* The final permutation for each byte is [2 7 6 1 3 0 4 5] */ \
    x = ((x & 0x08080808U) << 1) | \
        ((x & 0x32323232U) << 2) | \
        ((x & 0x01010101U) << 5) | \
        ((x & 0x80808080U) >> 6) | \
        ((x & 0x40404040U) >> 4) | \
        ((x & 0x04040404U) >> 2); \
} while (0)

/*
 * Apply the inverse of the SKINNY sbox.  The original version from the
 * specification is equivalent to:
 *
 * #define SBOX_MIX(x)
 *     (((~((((x) >> 1) | (x)) >> 2)) & 0x11111111U) ^ (x))
 * #define SBOX_SWAP(x)
 *     (((x) & 0xF9F9F9F9U) |
 *     (((x) >> 1) & 0x02020202U) |
 *     (((x) << 1) & 0x04040404U))
 * #define SBOX_PERMUTE_INV(x)
 *     ((((x) & 0x08080808U) << 1) |
 *      (((x) & 0x32323232U) << 2) |
 *      (((x) & 0x01010101U) << 5) |
 *      (((x) & 0xC0C0C0C0U) >> 5) |
 *      (((x) & 0x04040404U) >> 2))
 *
 * x = SBOX_SWAP(x);
 * x = SBOX_MIX(x);
 * x = SBOX_PERMUTE_INV(x);
 * x = SBOX_MIX(x);
 * x = SBOX_PERMUTE_INV(x);
 * x = SBOX_MIX(x);
 * x = SBOX_PERMUTE_INV(x);
 * return SBOX_MIX(x);
 *
 * However, we can mix the bits in their original positions and then
 * delay the SBOX_PERMUTE_INV and SBOX_SWAP steps to be performed with one
 * final permuatation.  This reduces the number of shift operations.
 */
#define skinny128_inv_sbox(x) \
do { \
    uint32_t y; \
    \
    /* Mix the bits */ \
    x = ~x; \
    y  = (((x >> 1) & (x >> 3)) & 0x01010101U); \
    x ^= (((x >> 2) & (x >> 3)) & 0x10101010U) ^ y; \
    y  = (((x >> 6) & (x >> 1)) & 0x02020202U); \
    x ^= (((x >> 1) & (x >> 2)) & 0x08080808U) ^ y; \
    y  = (((x << 2) & (x << 1)) & 0x80808080U); \
    x ^= (((x >> 1) & (x << 2)) & 0x04040404U) ^ y; \
    y  = (((x << 5) & (x << 1)) & 0x20202020U); \
    x ^= (((x << 4) & (x << 5)) & 0x40404040U) ^ y; \
    x = ~x; \
    \
    /* Permutation generated by http://programming.sirrida.de/calcperm.php */ \
    /* The final permutation for each byte is [5 3 0 4 6 7 2 1] */ \
    x = ((x & 0x01010101U) << 2) | \
        ((x & 0x04040404U) << 4) | \
        ((x & 0x02020202U) << 6) | \
        ((x & 0x20202020U) >> 5) | \
        ((x & 0xC8C8C8C8U) >> 2) | \
        ((x & 0x10101010U) >> 1); \
} while (0)

STATIC_INLINE void skinny128_fast_forward_tk(uint32_t *tk)
{
    /* This function is used to fast-forward the TK1 tweak value
     * to the value at the end of the key schedule for decryption.
     *
     * The tweak permutation repeats every 16 rounds, so SKINNY-128-384+
     * with 40 rounds is equivalent to applying the permutation 8 times:
     *
     * PT*8 = [5, 6, 3, 2, 7, 0, 1, 4, 13, 14, 11, 10, 15, 8, 9, 12]
     */
    uint32_t row0 = tk[0];
    uint32_t row1 = tk[1];
    uint32_t row2 = tk[2];
    uint32_t row3 = tk[3];
    tk[0] = ((row1 >>  8) & 0x0000FFFFU) |
            ((row0 >>  8) & 0x00FF0000U) |
            ((row0 <<  8) & 0xFF000000U);
    tk[1] = ((row1 >> 24) & 0x000000FFU) |
            ((row0 <<  8) & 0x00FFFF00U) |
            ((row1 << 24) & 0xFF000000U);
    tk[2] = ((row3 >>  8) & 0x0000FFFFU) |
            ((row2 >>  8) & 0x00FF0000U) |
            ((row2 <<  8) & 0xFF000000U);
    tk[3] = ((row3 >> 24) & 0x000000FFU) |
            ((row2 <<  8) & 0x00FFFF00U) |
            ((row3 << 24) & 0xFF000000U);
}

/** @endcond */

void skinny_plus_init
    (skinny_plus_key_schedule_t *ks, const unsigned char key[48])
{
    /* Copy TK1 as-is; it is expanded on the fly during encryption */
    memcpy(ks->TK1, key, 16);

    /* Generate the main key schedule from TK2 and TK3 */
    skinny_plus_init_without_tk1(ks, key + 16, key + 32);
}

void skinny_plus_init_without_tk1
    (skinny_plus_key_schedule_t *ks, const unsigned char *tk2,
     const unsigned char *tk3)
{
#if SKINNY_PLUS_VARIANT != SKINNY_PLUS_VARIANT_TINY
    uint32_t TK2[4];
    uint32_t TK3[4];
    uint32_t *schedule;
    unsigned round;
    uint8_t rc;
#endif

#if SKINNY_PLUS_VARIANT == SKINNY_PLUS_VARIANT_TINY
    /* Copy the input key as-is when using the tiny key schedule version */
    memcpy(ks->TK2, tk2, sizeof(ks->TK2));
    memcpy(ks->TK3, tk3, sizeof(ks->TK3));
#else
    /* Set the initial states of TK2 and TK3 */
    TK2[0] = le_load_word32(tk2);
    TK2[1] = le_load_word32(tk2 + 4);
    TK2[2] = le_load_word32(tk2 + 8);
    TK2[3] = le_load_word32(tk2 + 12);
    TK3[0] = le_load_word32(tk3);
    TK3[1] = le_load_word32(tk3 + 4);
    TK3[2] = le_load_word32(tk3 + 8);
    TK3[3] = le_load_word32(tk3 + 12);

    /* Set up the key schedule using TK2 and TK3.  TK1 is not added
     * to the key schedule because we will derive that part of the
     * schedule during encryption operations */
    schedule = ks->k;
    rc = 0;
    for (round = 0; round < SKINNY_PLUS_ROUNDS; round += 2, schedule += 4) {
        /* XOR the round constants with the current schedule words.
         * The round constants for the 3rd and 4th rows are
         * fixed and will be applied during encryption. */
        rc = (rc << 1) ^ ((rc >> 5) & 0x01) ^ ((rc >> 4) & 0x01) ^ 0x01;
        rc &= 0x3F;
        schedule[0] = TK2[0] ^ TK3[0] ^ (rc & 0x0F);
        schedule[1] = TK2[1] ^ TK3[1] ^ (rc >> 4);

        /* Permute the bottom half of TK2 and TK3 for the next round */
        skinny128_permute_tk_half(TK2[2], TK2[3]);
        skinny128_permute_tk_half(TK3[2], TK3[3]);
        skinny128_LFSR2(TK2[2]);
        skinny128_LFSR2(TK2[3]);
        skinny128_LFSR3(TK3[2]);
        skinny128_LFSR3(TK3[3]);

        /* XOR the round constants with the current schedule words.
         * The round constants for the 3rd and 4th rows are
         * fixed and will be applied during encryption. */
        rc = (rc << 1) ^ ((rc >> 5) & 0x01) ^ ((rc >> 4) & 0x01) ^ 0x01;
        rc &= 0x3F;
        schedule[2] = TK2[2] ^ TK3[2] ^ (rc & 0x0F);
        schedule[3] = TK2[3] ^ TK3[3] ^ (rc >> 4);

        /* Permute the top half of TK2 and TK3 for the next round */
        skinny128_permute_tk_half(TK2[0], TK2[1]);
        skinny128_permute_tk_half(TK3[0], TK3[1]);
        skinny128_LFSR2(TK2[0]);
        skinny128_LFSR2(TK2[1]);
        skinny128_LFSR3(TK3[0]);
        skinny128_LFSR3(TK3[1]);
    }
#endif
}

/**
 * \brief Performs an unrolled round for Skinny-128-384+ when only TK1 is
 * computed on the fly.
 *
 * \param s0 First word of the state.
 * \param s1 Second word of the state.
 * \param s2 Third word of the state.
 * \param s3 Fourth word of the state.
 * \param half 0 for the bottom half and 1 for the top half of the TK values.
 * \param offset Offset between 0 and 3 of the current unrolled round.
 */
#define skinny_plus_round(s0, s1, s2, s3, half, offset) \
    do { \
        /* Apply the S-box to all bytes in the state */ \
        skinny128_sbox(s0); \
        skinny128_sbox(s1); \
        skinny128_sbox(s2); \
        skinny128_sbox(s3); \
        \
        /* XOR the round constant and the subkey for this round */ \
        s0 ^= schedule[offset * 2]     ^ TK1[half * 2]; \
        s1 ^= schedule[offset * 2 + 1] ^ TK1[half * 2 + 1]; \
        s2 ^= 0x02; \
        \
        /* Shift the cells in the rows right, which moves the cell \
         * values up closer to the MSB.  That is, we do a left rotate \
         * on the word to rotate the cells in the word right */ \
        s1 = leftRotate8(s1); \
        s2 = leftRotate16(s2); \
        s3 = leftRotate24(s3); \
        \
        /* Mix the columns, but don't rotate the words yet */ \
        s1 ^= s2; \
        s2 ^= s0; \
        s3 ^= s2; \
        \
        /* Permute TK1 in-place for the next round */ \
        skinny128_permute_tk_half \
            (TK1[(1 - half) * 2], TK1[(1 - half) * 2 + 1]); \
    } while (0)

/**
 * \brief Performs an unrolled round for Skinny-128-384+ when the entire
 * tweakey schedule is computed on the fly.
 *
 * \param s0 First word of the state.
 * \param s1 Second word of the state.
 * \param s2 Third word of the state.
 * \param s3 Fourth word of the state.
 * \param half 0 for the bottom half and 1 for the top half of the TK values.
 */
#define skinny_plus_round_tk_full(s0, s1, s2, s3, half) \
    do { \
        /* Apply the S-box to all bytes in the state */ \
        skinny128_sbox(s0); \
        skinny128_sbox(s1); \
        skinny128_sbox(s2); \
        skinny128_sbox(s3); \
        \
        /* XOR the round constant and the subkey for this round */ \
        rc = (rc << 1) ^ ((rc >> 5) & 0x01) ^ ((rc >> 4) & 0x01) ^ 0x01; \
        rc &= 0x3F; \
        s0 ^= TK1[half * 2] ^ TK2[half * 2] ^ TK3[half * 2] ^ (rc & 0x0F); \
        s1 ^= TK1[half * 2 + 1] ^ TK2[half * 2 + 1] ^ TK3[half * 2 + 1] ^ \
              (rc >> 4); \
        s2 ^= 0x02; \
        \
        /* Shift the cells in the rows right, which moves the cell \
         * values up closer to the MSB.  That is, we do a left rotate \
         * on the word to rotate the cells in the word right */ \
        s1 = leftRotate8(s1); \
        s2 = leftRotate16(s2); \
        s3 = leftRotate24(s3); \
        \
        /* Mix the columns, but don't rotate the words yet */ \
        s1 ^= s2; \
        s2 ^= s0; \
        s3 ^= s2; \
        \
        /* Permute TK1, TK2, and TK3 in-place for the next round */ \
        skinny128_permute_tk_half \
            (TK1[(1 - half) * 2], TK1[(1 - half) * 2 + 1]); \
        skinny128_permute_tk_half \
            (TK2[(1 - half) * 2], TK2[(1 - half) * 2 + 1]); \
        skinny128_permute_tk_half \
            (TK3[(1 - half) * 2], TK3[(1 - half) * 2 + 1]); \
        skinny128_LFSR2(TK2[(1 - half) * 2]); \
        skinny128_LFSR2(TK2[(1 - half) * 2 + 1]); \
        skinny128_LFSR3(TK3[(1 - half) * 2]); \
        skinny128_LFSR3(TK3[(1 - half) * 2 + 1]); \
    } while (0)

/**
 * \brief Performs an unrolled inverse round for Skinny-128-384+ when
 * only TK1 is computed on the fly.
 *
 * \param s0 First word of the state.
 * \param s1 Second word of the state.
 * \param s2 Third word of the state.
 * \param s3 Fourth word of the state.
 * \param half 0 for the bottom half and 1 for the top half of the TK values.
 * \param offset Offset between 0 and 3 of the current unrolled round.
 */
#define skinny_plus_inv_round(s0, s1, s2, s3, half, offset) \
    do { \
        /* Inverse permutation on TK1 for this round */ \
        skinny128_inv_permute_tk_half \
            (TK1[(1 - half) * 2], TK1[(1 - half) * 2 + 1]); \
        \
        /* Inverse mix of the columns, without word rotation */ \
        s0 ^= s3; \
        s3 ^= s1; \
        s2 ^= s3; \
        \
        /* Inverse shift of the rows */ \
        s2 = leftRotate24(s2); \
        s3 = leftRotate16(s3); \
        s0 = leftRotate8(s0); \
        \
        /* Apply the subkey for this round */ \
        s1 ^= schedule[offset * 2]     ^ TK1[half * 2]; \
        s2 ^= schedule[offset * 2 + 1] ^ TK1[half * 2 + 1]; \
        s3 ^= 0x02; \
        \
        /* Apply the inverse of the S-box to all bytes in the state */ \
        skinny128_inv_sbox(s0); \
        skinny128_inv_sbox(s1); \
        skinny128_inv_sbox(s2); \
        skinny128_inv_sbox(s3); \
    } while (0)

/**
 * \brief Performs an unrolled inverse round for Skinny-128-384+ when the
 * entire tweakey schedule is computed on the fly.
 *
 * \param s0 First word of the state.
 * \param s1 Second word of the state.
 * \param s2 Third word of the state.
 * \param s3 Fourth word of the state.
 * \param half 0 for the bottom half and 1 for the top half of the TK values.
 */
#define skinny_plus_inv_round_tk_full(s0, s1, s2, s3, half) \
    do { \
        /* Inverse permutation on the tweakey for this round */ \
        skinny128_inv_permute_tk_half \
            (TK1[(1 - half) * 2], TK1[(1 - half) * 2 + 1]); \
        skinny128_inv_permute_tk_half \
            (TK2[(1 - half) * 2], TK2[(1 - half) * 2 + 1]); \
        skinny128_inv_permute_tk_half \
            (TK3[(1 - half) * 2], TK3[(1 - half) * 2 + 1]); \
        skinny128_LFSR3(TK2[(1 - half) * 2]); \
        skinny128_LFSR3(TK2[(1 - half) * 2 + 1]); \
        skinny128_LFSR2(TK3[(1 - half) * 2]); \
        skinny128_LFSR2(TK3[(1 - half) * 2 + 1]); \
        \
        /* Inverse mix of the columns, without word rotation */ \
        s0 ^= s3; \
        s3 ^= s1; \
        s2 ^= s3; \
        \
        /* Inverse shift of the rows */ \
        s2 = leftRotate24(s2); \
        s3 = leftRotate16(s3); \
        s0 = leftRotate8(s0); \
        \
        /* Apply the subkey for this round */ \
        rc = (rc >> 1) ^ (((rc << 5) ^ rc ^ 0x20) & 0x20); \
        s1 ^= TK1[half * 2] ^ TK2[half * 2] ^ TK3[half * 2] ^ (rc & 0x0F); \
        s2 ^= TK1[half * 2 + 1] ^ TK2[half * 2 + 1] ^ TK3[half * 2 + 1] ^ \
              (rc >> 4); \
        s3 ^= 0x02; \
        \
        /* Apply the inverse of the S-box to all bytes in the state */ \
        skinny128_inv_sbox(s0); \
        skinny128_inv_sbox(s1); \
        skinny128_inv_sbox(s2); \
        skinny128_inv_sbox(s3); \
    } while (0)

void skinny_plus_encrypt
    (const skinny_plus_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input)
{
    uint32_t s0, s1, s2, s3;
    uint32_t TK1[4];
#if SKINNY_PLUS_VARIANT == SKINNY_PLUS_VARIANT_TINY
    uint32_t TK2[4];
    uint32_t TK3[4];
    uint8_t rc = 0;
#else
    const uint32_t *schedule = ks->k;
#endif
    unsigned round;

    /* Unpack the input block into the state array */
    s0 = le_load_word32(input);
    s1 = le_load_word32(input + 4);
    s2 = le_load_word32(input + 8);
    s3 = le_load_word32(input + 12);

    /* Make a local copy of the tweakable part of the state */
    TK1[0] = le_load_word32(ks->TK1);
    TK1[1] = le_load_word32(ks->TK1 + 4);
    TK1[2] = le_load_word32(ks->TK1 + 8);
    TK1[3] = le_load_word32(ks->TK1 + 12);
#if SKINNY_PLUS_VARIANT == SKINNY_PLUS_VARIANT_TINY
    TK2[0] = le_load_word32(ks->TK2);
    TK2[1] = le_load_word32(ks->TK2 + 4);
    TK2[2] = le_load_word32(ks->TK2 + 8);
    TK2[3] = le_load_word32(ks->TK2 + 12);
    TK3[0] = le_load_word32(ks->TK3);
    TK3[1] = le_load_word32(ks->TK3 + 4);
    TK3[2] = le_load_word32(ks->TK3 + 8);
    TK3[3] = le_load_word32(ks->TK3 + 12);
#endif

    /* Perform all encryption rounds four at a time */
    for (round = 0; round < SKINNY_PLUS_ROUNDS; round += 4) {
#if SKINNY_PLUS_VARIANT == SKINNY_PLUS_VARIANT_TINY
        skinny_plus_round_tk_full(s0, s1, s2, s3, 0);
        skinny_plus_round_tk_full(s3, s0, s1, s2, 1);
        skinny_plus_round_tk_full(s2, s3, s0, s1, 0);
        skinny_plus_round_tk_full(s1, s2, s3, s0, 1);
#else
        skinny_plus_round(s0, s1, s2, s3, 0, 0);
        skinny_plus_round(s3, s0, s1, s2, 1, 1);
        skinny_plus_round(s2, s3, s0, s1, 0, 2);
        skinny_plus_round(s1, s2, s3, s0, 1, 3);
        schedule += 8;
#endif
    }

    /* Pack the result into the output buffer */
    le_store_word32(output,      s0);
    le_store_word32(output + 4,  s1);
    le_store_word32(output + 8,  s2);
    le_store_word32(output + 12, s3);
}

void skinny_plus_decrypt
    (const skinny_plus_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input)
{
    uint32_t s0, s1, s2, s3;
    uint32_t TK1[4];
#if SKINNY_PLUS_VARIANT == SKINNY_PLUS_VARIANT_TINY
    uint32_t TK2[4];
    uint32_t TK3[4];
    uint8_t rc = 0x34;
#else
    const uint32_t *schedule = &(ks->k[SKINNY_PLUS_ROUNDS * 2 - 8]);
#endif
    unsigned round;

    /* Unpack the input block into the state array */
    s0 = le_load_word32(input);
    s1 = le_load_word32(input + 4);
    s2 = le_load_word32(input + 8);
    s3 = le_load_word32(input + 12);

    /* Make a local copy of the tweakable part of the state, TK1 */
    TK1[0] = le_load_word32(ks->TK1);
    TK1[1] = le_load_word32(ks->TK1 + 4);
    TK1[2] = le_load_word32(ks->TK1 + 8);
    TK1[3] = le_load_word32(ks->TK1 + 12);
#if SKINNY_PLUS_VARIANT == SKINNY_PLUS_VARIANT_TINY
    TK2[0] = le_load_word32(ks->TK2);
    TK2[1] = le_load_word32(ks->TK2 + 4);
    TK2[2] = le_load_word32(ks->TK2 + 8);
    TK2[3] = le_load_word32(ks->TK2 + 12);
    TK3[0] = le_load_word32(ks->TK3);
    TK3[1] = le_load_word32(ks->TK3 + 4);
    TK3[2] = le_load_word32(ks->TK3 + 8);
    TK3[3] = le_load_word32(ks->TK3 + 12);
#endif

    /* Permute TK1 to fast-forward it to the end of the key schedule */
    skinny128_fast_forward_tk(TK1);
#if SKINNY_PLUS_VARIANT == SKINNY_PLUS_VARIANT_TINY
    skinny128_fast_forward_tk(TK2);
    skinny128_fast_forward_tk(TK3);
    for (round = 0; round < SKINNY_PLUS_ROUNDS; round += 2) {
        /* Also fast-forward the LFSR's on every byte of TK2 and TK3 */
        skinny128_LFSR2(TK2[0]);
        skinny128_LFSR2(TK2[1]);
        skinny128_LFSR2(TK2[2]);
        skinny128_LFSR2(TK2[3]);
        skinny128_LFSR3(TK3[0]);
        skinny128_LFSR3(TK3[1]);
        skinny128_LFSR3(TK3[2]);
        skinny128_LFSR3(TK3[3]);
    }
#endif

    /* Perform all decryption rounds four at a time */
    for (round = 0; round < SKINNY_PLUS_ROUNDS; round += 4) {
#if SKINNY_PLUS_VARIANT == SKINNY_PLUS_VARIANT_TINY
        skinny_plus_inv_round_tk_full(s0, s1, s2, s3, 1);
        skinny_plus_inv_round_tk_full(s1, s2, s3, s0, 0);
        skinny_plus_inv_round_tk_full(s2, s3, s0, s1, 1);
        skinny_plus_inv_round_tk_full(s3, s0, s1, s2, 0);
#else
        skinny_plus_inv_round(s0, s1, s2, s3, 1, 3);
        skinny_plus_inv_round(s1, s2, s3, s0, 0, 2);
        skinny_plus_inv_round(s2, s3, s0, s1, 1, 1);
        skinny_plus_inv_round(s3, s0, s1, s2, 0, 0);
        schedule -= 8;
#endif
    }

    /* Pack the result into the output buffer */
    le_store_word32(output,      s0);
    le_store_word32(output + 4,  s1);
    le_store_word32(output + 8,  s2);
    le_store_word32(output + 12, s3);
}

void skinny_plus_encrypt_tk_full
    (const unsigned char key[48], unsigned char *output,
     const unsigned char *input)
{
    uint32_t s0, s1, s2, s3;
    uint32_t TK1[4];
    uint32_t TK2[4];
    uint32_t TK3[4];
    unsigned round;
    uint8_t rc = 0;

    /* Unpack the input block into the state array */
    s0 = le_load_word32(input);
    s1 = le_load_word32(input + 4);
    s2 = le_load_word32(input + 8);
    s3 = le_load_word32(input + 12);

    /* Make a local copy of the tweakey */
    TK1[0] = le_load_word32(key);
    TK1[1] = le_load_word32(key + 4);
    TK1[2] = le_load_word32(key + 8);
    TK1[3] = le_load_word32(key + 12);
    TK2[0] = le_load_word32(key + 16);
    TK2[1] = le_load_word32(key + 20);
    TK2[2] = le_load_word32(key + 24);
    TK2[3] = le_load_word32(key + 28);
    TK3[0] = le_load_word32(key + 32);
    TK3[1] = le_load_word32(key + 36);
    TK3[2] = le_load_word32(key + 40);
    TK3[3] = le_load_word32(key + 44);

    /* Perform all encryption rounds four at a time */
    for (round = 0; round < SKINNY_PLUS_ROUNDS; round += 4) {
        skinny_plus_round_tk_full(s0, s1, s2, s3, 0);
        skinny_plus_round_tk_full(s3, s0, s1, s2, 1);
        skinny_plus_round_tk_full(s2, s3, s0, s1, 0);
        skinny_plus_round_tk_full(s1, s2, s3, s0, 1);
    }

    /* Pack the result into the output buffer */
    le_store_word32(output,      s0);
    le_store_word32(output + 4,  s1);
    le_store_word32(output + 8,  s2);
    le_store_word32(output + 12, s3);
}

void skinny_plus_decrypt_tk_full
    (const unsigned char key[48], unsigned char *output,
     const unsigned char *input)
{
    uint32_t s0, s1, s2, s3;
    uint32_t TK1[4];
    uint32_t TK2[4];
    uint32_t TK3[4];
    uint8_t rc = 0x34;
    unsigned round;

    /* Unpack the input block into the state array */
    s0 = le_load_word32(input);
    s1 = le_load_word32(input + 4);
    s2 = le_load_word32(input + 8);
    s3 = le_load_word32(input + 12);

    /* Make a local copy of the tweakey */
    TK1[0] = le_load_word32(key);
    TK1[1] = le_load_word32(key + 4);
    TK1[2] = le_load_word32(key + 8);
    TK1[3] = le_load_word32(key + 12);
    TK2[0] = le_load_word32(key + 16);
    TK2[1] = le_load_word32(key + 20);
    TK2[2] = le_load_word32(key + 24);
    TK2[3] = le_load_word32(key + 28);
    TK3[0] = le_load_word32(key + 32);
    TK3[1] = le_load_word32(key + 36);
    TK3[2] = le_load_word32(key + 40);
    TK3[3] = le_load_word32(key + 44);

    /* Permute the tweakey to fast-forward it to the end of the key schedule */
    skinny128_fast_forward_tk(TK1);
    skinny128_fast_forward_tk(TK2);
    skinny128_fast_forward_tk(TK3);
    for (round = 0; round < SKINNY_PLUS_ROUNDS; round += 2) {
        /* Also fast-forward the LFSR's on every byte of TK2 and TK3 */
        skinny128_LFSR2(TK2[0]);
        skinny128_LFSR2(TK2[1]);
        skinny128_LFSR2(TK2[2]);
        skinny128_LFSR2(TK2[3]);
        skinny128_LFSR3(TK3[0]);
        skinny128_LFSR3(TK3[1]);
        skinny128_LFSR3(TK3[2]);
        skinny128_LFSR3(TK3[3]);
    }

    /* Perform all decryption rounds four at a time */
    for (round = 0; round < SKINNY_PLUS_ROUNDS; round += 4) {
        skinny_plus_inv_round_tk_full(s0, s1, s2, s3, 1);
        skinny_plus_inv_round_tk_full(s1, s2, s3, s0, 0);
        skinny_plus_inv_round_tk_full(s2, s3, s0, s1, 1);
        skinny_plus_inv_round_tk_full(s3, s0, s1, s2, 0);
    }

    /* Pack the result into the output buffer */
    le_store_word32(output,      s0);
    le_store_word32(output + 4,  s1);
    le_store_word32(output + 8,  s2);
    le_store_word32(output + 12, s3);
}

#endif /* !SKINNY_PLUS_VARIANT_FULL */

#else /* SKINNY_PLUS_VARIANT_ASM */

/* Assembly code versions have skinny_plus_init_without_tk1() only */

void skinny_plus_init
    (skinny_plus_key_schedule_t *ks, const unsigned char key[48])
{
    /* Copy TK1 as-is; it is expanded on the fly during encryption */
    memcpy(ks->TK1, key, 16);

    /* Generate the main key schedule from TK2 and TK3 */
    skinny_plus_init_without_tk1(ks, key + 16, key + 32);
}

#if SKINNY_PLUS_VARIANT == SKINNY_PLUS_VARIANT_FULL

/* Define the tk_full() functions in terms of the basic assembly functions */

void skinny_plus_encrypt_tk_full
    (const unsigned char key[48], unsigned char *output,
     const unsigned char *input)
{
    skinny_plus_key_schedule_t ks;
    memcpy(ks.TK1, key, 16);
    skinny_plus_init_without_tk1(&ks, key + 16, key + 32);
    skinny_plus_encrypt(&ks, output, input);
}

void skinny_plus_decrypt_tk_full
    (const unsigned char key[48], unsigned char *output,
     const unsigned char *input)
{
    skinny_plus_key_schedule_t ks;
    memcpy(ks.TK1, key, 16);
    skinny_plus_init_without_tk1(&ks, key + 16, key + 32);
    skinny_plus_decrypt(&ks, output, input);
}

#endif

#endif /* SKINNY_PLUS_VARIANT_ASM */
