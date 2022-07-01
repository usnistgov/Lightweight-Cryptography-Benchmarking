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

#include "romulus-hash.h"
#include "internal-skinny-plus.h"
#include "internal-util.h"
#include <string.h>

/**
 * \var ROMULUS_HASH_KEY_SCHEDULE
 * \brief Define to 1 to use a full key schedule for the hash block operation.
 *
 * This option will use a significant amount of stack space but may be
 * faster because it avoids expanding the key schedule twice in the
 * skinny_plus_encrypt_tk_full() calls within romulus_hash_process_chunk().
 */
#if defined(__AVR__)
#define ROMULUS_HASH_KEY_SCHEDULE 0
#elif SKINNY_PLUS_VARIANT == SKINNY_PLUS_VARIANT_FULL
#define ROMULUS_HASH_KEY_SCHEDULE 1
#else
#define ROMULUS_HASH_KEY_SCHEDULE 0
#endif

int romulus_hash
    (unsigned char *out, const unsigned char *in, size_t inlen)
{
    romulus_hash_state_t state;
    romulus_hash_init(&state);
    romulus_hash_update(&state, in, inlen);
    romulus_hash_finalize(&state, out);
    return 0;
}

void romulus_hash_init(romulus_hash_state_t *state)
{
    memset(state, 0, sizeof(romulus_hash_state_t));
}

/**
 * \brief Processes a full chunk of input data.
 *
 * \param Points to the Romulus-H hash state.
 */
void romulus_hash_process_chunk(romulus_hash_state_t *state)
{
    /*
     * TK = g + M where g is TK1 and TK23 = M is the 32 bytes of the message.
     * h is a separate 16 byte rolling state value.  Compute:
     *
     *      g' = h
     *      h' = h
     *      g' ^= 0x01
     *      h = encrypt(TK, h')
     *      g = encrypt(TK, g')
     *      h ^= h'
     *      g ^= h'
     *      g ^= 0x01
     */
#if ROMULUS_HASH_KEY_SCHEDULE
    unsigned char h[16];
    skinny_plus_key_schedule_t ks;
    memcpy(h, state->s.h, 16);
    skinny_plus_init(&ks, state->s.tk);
    skinny_plus_encrypt(&ks, state->s.h, h);
    h[0] ^= 0x01;
    skinny_plus_encrypt(&ks, state->s.tk, h);
    lw_xor_block(state->s.h, h, 16);
    lw_xor_block(state->s.tk, h, 16);
    state->s.h[0] ^= 0x01;
#else
    unsigned char h[16];
    memcpy(h, state->s.h, 16);
    skinny_plus_encrypt_tk_full(state->s.tk, state->s.h, h);
    h[0] ^= 0x01;
    skinny_plus_encrypt_tk_full(state->s.tk, state->s.tk, h);
    lw_xor_block(state->s.h, h, 16);
    lw_xor_block(state->s.tk, h, 16);
    state->s.h[0] ^= 0x01;
#endif
}

void romulus_hash_update
    (romulus_hash_state_t *state, const unsigned char *in, size_t inlen)
{
    unsigned temp;

    if (state->s.mode) {
        /* We were squeezing output - go back to the absorb phase */
        state->s.mode = 0;
        state->s.count = 0;
        romulus_hash_process_chunk(state);
    }

    /* Handle the partial left-over block from last time */
    if (state->s.count) {
        temp = ROMULUS_HASH_RATE - state->s.count;
        if (temp > inlen) {
            temp = (unsigned)inlen;
            memcpy(state->s.tk + 16 + state->s.count, in, temp);
            state->s.count += temp;
            return;
        }
        memcpy(state->s.tk + 16 + state->s.count, in, temp);
        state->s.count = 0;
        in += temp;
        inlen -= temp;
        romulus_hash_process_chunk(state);
    }

    /* Process full blocks that are aligned at state->s.count == 0 */
    while (inlen >= ROMULUS_HASH_RATE) {
        memcpy(state->s.tk + 16, in, ROMULUS_HASH_RATE);
        in += ROMULUS_HASH_RATE;
        inlen -= ROMULUS_HASH_RATE;
        romulus_hash_process_chunk(state);
    }

    /* Process the left-over block at the end of the input */
    temp = (unsigned)inlen;
    memcpy(state->s.tk + 16, in, temp);
    state->s.count = temp;
}

void romulus_hash_finalize(romulus_hash_state_t *state, unsigned char *out)
{
    if (!state->s.mode) {
        /* We were still absorbing, so pad and process the last chunk */
        memset(state->s.tk + 16 + state->s.count, 0,
               ROMULUS_HASH_RATE - 1 - state->s.count);
        state->s.tk[47] = state->s.count;
        state->s.h[0] ^= 0x02;
        romulus_hash_process_chunk(state);
        state->s.mode = 1;
        state->s.count = 0;
    }

    /* The hash value is h concatenated with g, where g is in the tweakey */
    memcpy(out, state->s.h, 16);
    memcpy(out + 16, state->s.tk, 16);
}
