/*
 * SKINNY-HASH Reference C Implementation
 * 
 * Copyright 2018:
 *     Jeremy Jean for the SKINNY Team
 *     https://sites.google.com/site/skinnycipher/
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "skinny_hash.h"
#include "skinny_reference.h" /* Defines the SKINNY TBC family */

/*
** This file implements the two SKINNY-HASH members.
**
** SKINNY-HASH-TK3:
**      1: SKINNY-128-384 TBC with 256-bit outputs (PRIMARY)
** TK2 members:
**      2: SKINNY-128-256 TBC with 128-bit outputs
*/
#define SKINNY_HASH_MEMBER 2

/*******************************************************************************
** Constant definitions
*******************************************************************************/

/*
** Defines the SKINNY-HASH instances.
*/
#if SKINNY_HASH_MEMBER == 1
    #define TWEAKEY_STATE_SIZE 48 /* TK3                 */
    #define DIGEST_SIZE        32 /* 256-bit outputs     */
    #define RATE               16 /* 128-bit rate        */
    #define CAPACITY           32 /* 256-bit capacity    */
    #define SKINNY_F  skinny_F384 /* Underlying function */

#elif SKINNY_HASH_MEMBER == 2
    #define TWEAKEY_STATE_SIZE 32 /* TK2                 */
    #define DIGEST_SIZE        16 /* 128-bit outputs     */
    #define RATE                4 /* 32-bit rate         */
    #define CAPACITY           28 /* 224-bit capacity    */
    #define SKINNY_F  skinny_F256 /* Underlying function */

#else
    #error "Not implemented."
#endif

/*
** Underlying function used in the sponge function for SKINNY-HASH-TK3
*/
#if SKINNY_HASH_MEMBER == 1
static void skinny_F384(uint8_t* state) {

    uint8_t tweakey[48];
    uint8_t tmp_in[16];
    uint8_t tmp_out[16];

    memset(tmp_in, 0, sizeof(tmp_in));
    memcpy(tweakey, state, 48);

    /* First TBC call with input 0 */
    tmp_in[0] = 0;
    enc(tmp_in, tweakey, tmp_out, 5);
    memcpy(state, tmp_out, 16);

    /* Second TBC call with input 1 */
    tmp_in[0] = 1;
    enc(tmp_in, tweakey, tmp_out, 5);
    memcpy(state+16, tmp_out, 16);

    /* Third TBC call with input 2 */
    tmp_in[0] = 2;
    enc(tmp_in, tweakey, tmp_out, 5);
    memcpy(state+32, tmp_out, 16);
}
#elif SKINNY_HASH_MEMBER == 2
/*
** Underlying function used in the sponge function for SKINNY-HASH-TK2
*/
static void skinny_F256(uint8_t* state) {

    uint8_t tweakey[32];
    uint8_t tmp_in[16];
    uint8_t tmp_out[16];

    memset(tmp_in, 0, sizeof(tmp_in));
    memcpy(tweakey, state, 32);

    /* First TBC call with input 0 */
    tmp_in[0] = 0;
    enc(tmp_in, tweakey, tmp_out, 4);
    memcpy(state, tmp_out, 16);

    /* Second TBC call with input 1 */
    tmp_in[0] = 1;
    enc(tmp_in, tweakey, tmp_out, 4);
    memcpy(state+16, tmp_out, 16);
}
#endif

/*
** XOR an input block to another input block
*/
static void xor_values(uint8_t *v1, const uint8_t *v2, const int len) {
    for (int i=0; i<len; i++) {
        v1[i] ^= v2[i];
    }
}

/*
** SKINNY-HASH
*/
int skinny_hash(uint8_t *out,
                 const uint8_t *message,
                 unsigned long long m_len)

{
    unsigned long long i;
    uint8_t state[TWEAKEY_STATE_SIZE];
    uint8_t last_block[RATE];

    /* Initialize the internal state */
    memset(state, 0, sizeof(state));
    state[RATE] = 0x80;

    i = 0;
    while (RATE*(i+1) <= m_len) {

        /* Inject the message into the rate part of the internal state */
        xor_values(state, message + RATE*i, RATE);

        /* Apply the sponge function */
        SKINNY_F(state);

        /* Update the counter (number of blocks) */
        i++;
    }

   /* Process incomplete block */
   if (m_len > RATE*i) {

        /* Prepare the last padded block */
        memset(last_block, 0, RATE);
        memcpy(last_block, message+RATE*i, m_len-RATE*i);
        last_block[m_len-RATE*i] = 0x80;

        /* Inject the message into the rate part of the internal state */
        xor_values(state, last_block, RATE);

        /* Apply the sponge function */
        SKINNY_F(state);

    } else {

        /* Prepare the last padded block */
        memset(last_block, 0, RATE);
        last_block[0] = 0x80;

        /* Inject padded block into the rate part */
        xor_values(state, last_block, RATE);

        /* Apply the sponge function */
        SKINNY_F(state);

    }

    /* Finished absorbing message, now extract.                      */
    /* Note that for the tk2 hash funtion, the rate part of the      */
    /* squeezing phase is larger than the rate part of the absorbing */
    /* phase (namely, 128 vs. 32 bits)                               */

    memcpy(out, state, 16);
    SKINNY_F(state);
    memcpy(out+16, state, 16);

    return 0;
}
