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

#include "forkae.h"
#include "internal-forkskinny.h"
#include <string.h>

aead_cipher_t const forkae_paef_64_192_cipher = {
    "PAEF-ForkSkinny-64-192",
    FORKAE_PAEF_64_192_KEY_SIZE,
    FORKAE_PAEF_64_192_NONCE_SIZE,
    FORKAE_PAEF_64_192_TAG_SIZE,
    AEAD_FLAG_NONE,
    forkae_paef_64_192_aead_encrypt,
    forkae_paef_64_192_aead_decrypt
};

aead_cipher_t const forkae_paef_128_192_cipher = {
    "PAEF-ForkSkinny-128-192",
    FORKAE_PAEF_128_192_KEY_SIZE,
    FORKAE_PAEF_128_192_NONCE_SIZE,
    FORKAE_PAEF_128_192_TAG_SIZE,
    AEAD_FLAG_NONE,
    forkae_paef_128_192_aead_encrypt,
    forkae_paef_128_192_aead_decrypt
};

aead_cipher_t const forkae_paef_128_256_cipher = {
    "PAEF-ForkSkinny-128-256",
    FORKAE_PAEF_128_256_KEY_SIZE,
    FORKAE_PAEF_128_256_NONCE_SIZE,
    FORKAE_PAEF_128_256_TAG_SIZE,
    AEAD_FLAG_NONE,
    forkae_paef_128_256_aead_encrypt,
    forkae_paef_128_256_aead_decrypt
};

aead_cipher_t const forkae_paef_128_288_cipher = {
    "PAEF-ForkSkinny-128-288",
    FORKAE_PAEF_128_288_KEY_SIZE,
    FORKAE_PAEF_128_288_NONCE_SIZE,
    FORKAE_PAEF_128_288_TAG_SIZE,
    AEAD_FLAG_NONE,
    forkae_paef_128_288_aead_encrypt,
    forkae_paef_128_288_aead_decrypt
};

aead_cipher_t const forkae_saef_128_192_cipher = {
    "SAEF-ForkSkinny-128-192",
    FORKAE_SAEF_128_192_KEY_SIZE,
    FORKAE_SAEF_128_192_NONCE_SIZE,
    FORKAE_SAEF_128_192_TAG_SIZE,
    AEAD_FLAG_NONE,
    forkae_saef_128_192_aead_encrypt,
    forkae_saef_128_192_aead_decrypt
};

aead_cipher_t const forkae_saef_128_256_cipher = {
    "SAEF-ForkSkinny-128-256",
    FORKAE_SAEF_128_256_KEY_SIZE,
    FORKAE_SAEF_128_256_NONCE_SIZE,
    FORKAE_SAEF_128_256_TAG_SIZE,
    AEAD_FLAG_NONE,
    forkae_saef_128_256_aead_encrypt,
    forkae_saef_128_256_aead_decrypt
};

/* PAEF-ForkSkinny-64-192 */
#define FORKAE_ALG_NAME forkae_paef_64_192
#define FORKAE_BLOCK_SIZE 8
#define FORKAE_NONCE_SIZE FORKAE_PAEF_64_192_NONCE_SIZE
#define FORKAE_COUNTER_SIZE 2
#define FORKAE_TWEAKEY_SIZE 24
#define FORKAE_BLOCK_FUNC forkskinny_64_192
#include "internal-forkae-paef.h"

/* PAEF-ForkSkinny-128-192 */
#define FORKAE_ALG_NAME forkae_paef_128_192
#define FORKAE_BLOCK_SIZE 16
#define FORKAE_NONCE_SIZE FORKAE_PAEF_128_192_NONCE_SIZE
#define FORKAE_COUNTER_SIZE 2
#define FORKAE_TWEAKEY_SIZE 32
#define FORKAE_BLOCK_FUNC forkskinny_128_256
#include "internal-forkae-paef.h"

/* PAEF-ForkSkinny-128-256 */
#define FORKAE_ALG_NAME forkae_paef_128_256
#define FORKAE_BLOCK_SIZE 16
#define FORKAE_NONCE_SIZE FORKAE_PAEF_128_256_NONCE_SIZE
#define FORKAE_COUNTER_SIZE 2
#define FORKAE_TWEAKEY_SIZE 32
#define FORKAE_BLOCK_FUNC forkskinny_128_256
#include "internal-forkae-paef.h"

/* PAEF-ForkSkinny-128-288 */
#define FORKAE_ALG_NAME forkae_paef_128_288
#define FORKAE_BLOCK_SIZE 16
#define FORKAE_NONCE_SIZE FORKAE_PAEF_128_288_NONCE_SIZE
#define FORKAE_COUNTER_SIZE 7
#define FORKAE_TWEAKEY_SIZE 48
#define FORKAE_BLOCK_FUNC forkskinny_128_384
#include "internal-forkae-paef.h"

/* SAEF-ForkSkinny-128-192 */
#define FORKAE_ALG_NAME forkae_saef_128_192
#define FORKAE_BLOCK_SIZE 16
#define FORKAE_NONCE_SIZE FORKAE_SAEF_128_192_NONCE_SIZE
#define FORKAE_TWEAKEY_SIZE 32
#define FORKAE_TWEAKEY_REDUCED_SIZE 24
#define FORKAE_BLOCK_FUNC forkskinny_128_256
#include "internal-forkae-saef.h"

/* SAEF-ForkSkinny-128-256 */
#define FORKAE_ALG_NAME forkae_saef_128_256
#define FORKAE_BLOCK_SIZE 16
#define FORKAE_NONCE_SIZE FORKAE_SAEF_128_256_NONCE_SIZE
#define FORKAE_TWEAKEY_SIZE 32
#define FORKAE_TWEAKEY_REDUCED_SIZE 32
#define FORKAE_BLOCK_FUNC forkskinny_128_256
#include "internal-forkae-saef.h"

/* Helper functions to implement the forking encrypt/decrypt block operations
 * on top of the basic "perform N rounds" functions in internal-forkskinny.c */

void forkskinny_128_256_encrypt
    (const unsigned char key[32], unsigned char *output_left,
     unsigned char *output_right, const unsigned char *input)
{
    forkskinny_128_256_state_t state;
    forkskinny_128_256_tweakey_schedule_t tks;

    /* Iterate the tweakey schedule */
	if (output_left && output_right){
		forkskinny_128_256_init_tks(&tks, key, FORKSKINNY_128_256_ROUNDS_BEFORE + 2*FORKSKINNY_128_256_ROUNDS_AFTER);
	}
	else{
		forkskinny_128_256_init_tks(&tks, key, FORKSKINNY_128_256_ROUNDS_BEFORE + FORKSKINNY_128_256_ROUNDS_AFTER);
	}

    /* Unpack the input */
    state.S[0] = le_load_word32(input);
    state.S[1] = le_load_word32(input + 4);
    state.S[2] = le_load_word32(input + 8);
    state.S[3] = le_load_word32(input + 12);

    /* Run all of the rounds before the forking point */
    forkskinny_128_256_rounds(&state, &tks, 0, FORKSKINNY_128_256_ROUNDS_BEFORE);

    /* Determine which output blocks we need */
    if (output_left && output_right) {
        /* We need both outputs so save the state at the forking point */
        uint32_t F[4];
        F[0] = state.S[0];
        F[1] = state.S[1];
        F[2] = state.S[2];
        F[3] = state.S[3];

        /* Generate the right output block */
        forkskinny_128_256_rounds
            (&state, &tks, FORKSKINNY_128_256_ROUNDS_BEFORE,
             FORKSKINNY_128_256_ROUNDS_BEFORE +
             FORKSKINNY_128_256_ROUNDS_AFTER);
        le_store_word32(output_right,      state.S[0]);
        le_store_word32(output_right + 4,  state.S[1]);
        le_store_word32(output_right + 8,  state.S[2]);
        le_store_word32(output_right + 12, state.S[3]);

        /* Restore the state at the forking point */
        state.S[0] = F[0];
        state.S[1] = F[1];
        state.S[2] = F[2];
        state.S[3] = F[3];
    }
    if (output_left) {
        /* Generate the left output block */
        state.S[0] ^= 0x08040201U; /* Branching constant */
        state.S[1] ^= 0x82412010U;
        state.S[2] ^= 0x28140a05U;
        state.S[3] ^= 0x8844a251U;
        forkskinny_128_256_rounds
            (&state, &tks, FORKSKINNY_128_256_ROUNDS_BEFORE +
                     FORKSKINNY_128_256_ROUNDS_AFTER,
             FORKSKINNY_128_256_ROUNDS_BEFORE +
             FORKSKINNY_128_256_ROUNDS_AFTER * 2);
        le_store_word32(output_left,      state.S[0]);
        le_store_word32(output_left + 4,  state.S[1]);
        le_store_word32(output_left + 8,  state.S[2]);
        le_store_word32(output_left + 12, state.S[3]);
    } else {
        /* We only need the right output block */
        forkskinny_128_256_rounds
            (&state, &tks, FORKSKINNY_128_256_ROUNDS_BEFORE,
             FORKSKINNY_128_256_ROUNDS_BEFORE +
             FORKSKINNY_128_256_ROUNDS_AFTER);
        le_store_word32(output_right,      state.S[0]);
        le_store_word32(output_right + 4,  state.S[1]);
        le_store_word32(output_right + 8,  state.S[2]);
        le_store_word32(output_right + 12, state.S[3]);
    }
}

void forkskinny_128_256_decrypt
    (const unsigned char key[32], unsigned char *output_left,
     unsigned char *output_right, const unsigned char *input)
{
    forkskinny_128_256_state_t state;
    forkskinny_128_256_state_t fstate;
    forkskinny_128_256_tweakey_schedule_t tks;

    /* Iterate the tweakey schedule */
	forkskinny_128_256_init_tks(&tks, key, FORKSKINNY_128_256_ROUNDS_BEFORE + 2*FORKSKINNY_128_256_ROUNDS_AFTER);


    /* Unpack the input */
    state.S[0] = le_load_word32(input);
    state.S[1] = le_load_word32(input + 4);
    state.S[2] = le_load_word32(input + 8);
    state.S[3] = le_load_word32(input + 12);

    /* Perform the "after" rounds on the input to get back
     * to the forking point in the cipher */
    forkskinny_128_256_inv_rounds
        (&state, &tks, FORKSKINNY_128_256_ROUNDS_BEFORE +
                 FORKSKINNY_128_256_ROUNDS_AFTER * 2,
         FORKSKINNY_128_256_ROUNDS_BEFORE +
         FORKSKINNY_128_256_ROUNDS_AFTER);

    /* Remove the branching constant */
    state.S[0] ^= 0x08040201U;
    state.S[1] ^= 0x82412010U;
    state.S[2] ^= 0x28140a05U;
    state.S[3] ^= 0x8844a251U;

    /* Save the state and the tweakey at the forking point */
    fstate = state;

    /* Generate the left output block after another "before" rounds */
    forkskinny_128_256_inv_rounds
        (&state, &tks, FORKSKINNY_128_256_ROUNDS_BEFORE, 0);
    le_store_word32(output_left,      state.S[0]);
    le_store_word32(output_left + 4,  state.S[1]);
    le_store_word32(output_left + 8,  state.S[2]);
    le_store_word32(output_left + 12, state.S[3]);

    /* Generate the right output block by going forward "after"
     * rounds from the forking point */
    forkskinny_128_256_rounds
        (&fstate, &tks, FORKSKINNY_128_256_ROUNDS_BEFORE,
         FORKSKINNY_128_256_ROUNDS_BEFORE +
         FORKSKINNY_128_256_ROUNDS_AFTER);
    le_store_word32(output_right,      fstate.S[0]);
    le_store_word32(output_right + 4,  fstate.S[1]);
    le_store_word32(output_right + 8,  fstate.S[2]);
    le_store_word32(output_right + 12, fstate.S[3]);
}

void forkskinny_128_384_encrypt
    (const unsigned char key[48], unsigned char *output_left,
     unsigned char *output_right, const unsigned char *input)
{
    forkskinny_128_384_state_t state;
    forkskinny_128_384_tweakey_schedule_t tks;

    /* Iterate key schedule */
	if (output_left && output_right){
		forkskinny_128_384_init_tks(&tks, key, FORKSKINNY_128_384_ROUNDS_BEFORE + 2*FORKSKINNY_128_384_ROUNDS_AFTER);
	}
	else{
		forkskinny_128_384_init_tks(&tks, key, FORKSKINNY_128_384_ROUNDS_BEFORE + FORKSKINNY_128_384_ROUNDS_AFTER);
	}

    /* Unpack the input */
    state.S[0] = le_load_word32(input);
    state.S[1] = le_load_word32(input + 4);
    state.S[2] = le_load_word32(input + 8);
    state.S[3] = le_load_word32(input + 12);

    /* Run all of the rounds before the forking point */
    forkskinny_128_384_rounds(&state, &tks, 0, FORKSKINNY_128_384_ROUNDS_BEFORE);

    /* Determine which output blocks we need */
    if (output_left && output_right) {
        /* We need both outputs so save the state at the forking point */
        uint32_t F[4];
        F[0] = state.S[0];
        F[1] = state.S[1];
        F[2] = state.S[2];
        F[3] = state.S[3];

        /* Generate the right output block */
        forkskinny_128_384_rounds
            (&state, &tks, FORKSKINNY_128_384_ROUNDS_BEFORE,
             FORKSKINNY_128_384_ROUNDS_BEFORE +
             FORKSKINNY_128_384_ROUNDS_AFTER);
        le_store_word32(output_right,      state.S[0]);
        le_store_word32(output_right + 4,  state.S[1]);
        le_store_word32(output_right + 8,  state.S[2]);
        le_store_word32(output_right + 12, state.S[3]);

        /* Restore the state at the forking point */
        state.S[0] = F[0];
        state.S[1] = F[1];
        state.S[2] = F[2];
        state.S[3] = F[3];
    }
    if (output_left) {
        /* Generate the left output block */
        state.S[0] ^= 0x08040201U; /* Branching constant */
        state.S[1] ^= 0x82412010U;
        state.S[2] ^= 0x28140a05U;
        state.S[3] ^= 0x8844a251U;
        forkskinny_128_384_rounds
            (&state, &tks, FORKSKINNY_128_384_ROUNDS_BEFORE +
                     FORKSKINNY_128_384_ROUNDS_AFTER,
             FORKSKINNY_128_384_ROUNDS_BEFORE +
             FORKSKINNY_128_384_ROUNDS_AFTER * 2);
        le_store_word32(output_left,      state.S[0]);
        le_store_word32(output_left + 4,  state.S[1]);
        le_store_word32(output_left + 8,  state.S[2]);
        le_store_word32(output_left + 12, state.S[3]);
    } else {
        /* We only need the right output block */
        forkskinny_128_384_rounds
            (&state, &tks, FORKSKINNY_128_384_ROUNDS_BEFORE,
             FORKSKINNY_128_384_ROUNDS_BEFORE +
             FORKSKINNY_128_384_ROUNDS_AFTER);
        le_store_word32(output_right,      state.S[0]);
        le_store_word32(output_right + 4,  state.S[1]);
        le_store_word32(output_right + 8,  state.S[2]);
        le_store_word32(output_right + 12, state.S[3]);
    }
}

void forkskinny_128_384_decrypt
    (const unsigned char key[48], unsigned char *output_left,
     unsigned char *output_right, const unsigned char *input)
{
    forkskinny_128_384_state_t state;
    forkskinny_128_384_state_t fstate;
    forkskinny_128_384_tweakey_schedule_t tks;

    /* Iterate key schedule */
	forkskinny_128_384_init_tks(&tks, key, FORKSKINNY_128_384_ROUNDS_BEFORE + 2*FORKSKINNY_128_384_ROUNDS_AFTER);


    /* Unpack the input */
    state.S[0] = le_load_word32(input);
    state.S[1] = le_load_word32(input + 4);
    state.S[2] = le_load_word32(input + 8);
    state.S[3] = le_load_word32(input + 12);

    /* Perform the "after" rounds on the input to get back
     * to the forking point in the cipher */
    forkskinny_128_384_inv_rounds
        (&state, &tks, FORKSKINNY_128_384_ROUNDS_BEFORE +
                 FORKSKINNY_128_384_ROUNDS_AFTER * 2,
         FORKSKINNY_128_384_ROUNDS_BEFORE +
         FORKSKINNY_128_384_ROUNDS_AFTER);

    /* Remove the branching constant */
    state.S[0] ^= 0x08040201U;
    state.S[1] ^= 0x82412010U;
    state.S[2] ^= 0x28140a05U;
    state.S[3] ^= 0x8844a251U;

    /* Save the state and the tweakey at the forking point */
    fstate = state;

    /* Generate the left output block after another "before" rounds */
    forkskinny_128_384_inv_rounds(&state, &tks, FORKSKINNY_128_384_ROUNDS_BEFORE, 0);
    le_store_word32(output_left,      state.S[0]);
    le_store_word32(output_left + 4,  state.S[1]);
    le_store_word32(output_left + 8,  state.S[2]);
    le_store_word32(output_left + 12, state.S[3]);

    /* Generate the right output block by going forward "after"
     * rounds from the forking point */
    forkskinny_128_384_rounds
        (&fstate, &tks, FORKSKINNY_128_384_ROUNDS_BEFORE,
         FORKSKINNY_128_384_ROUNDS_BEFORE +
         FORKSKINNY_128_384_ROUNDS_AFTER);
    le_store_word32(output_right,      fstate.S[0]);
    le_store_word32(output_right + 4,  fstate.S[1]);
    le_store_word32(output_right + 8,  fstate.S[2]);
    le_store_word32(output_right + 12, fstate.S[3]);
}

void forkskinny_64_192_encrypt
    (const unsigned char key[24], unsigned char *output_left,
     unsigned char *output_right, const unsigned char *input)
{
    forkskinny_64_192_state_t state;
    forkskinny_64_192_tweakey_schedule_t tks;

	/* Iterate key schedule */
	if (output_left && output_right){
		forkskinny_64_192_init_tks(&tks, key, FORKSKINNY_64_192_ROUNDS_BEFORE + 2*FORKSKINNY_64_192_ROUNDS_AFTER);
	}
	else{
		forkskinny_64_192_init_tks(&tks, key, FORKSKINNY_64_192_ROUNDS_BEFORE + FORKSKINNY_64_192_ROUNDS_AFTER);
	}

    /* Unpack the input */
    state.S[0] = be_load_word16(input);
    state.S[1] = be_load_word16(input + 2);
    state.S[2] = be_load_word16(input + 4);
    state.S[3] = be_load_word16(input + 6);

    /* Run all of the rounds before the forking point */
    forkskinny_64_192_rounds(&state, &tks, 0, FORKSKINNY_64_192_ROUNDS_BEFORE);

    /* Determine which output blocks we need */
    if (output_left && output_right) {
        /* We need both outputs so save the state at the forking point */
        uint16_t F[4];
        F[0] = state.S[0];
        F[1] = state.S[1];
        F[2] = state.S[2];
        F[3] = state.S[3];

        /* Generate the right output block */
        forkskinny_64_192_rounds
            (&state, &tks, FORKSKINNY_64_192_ROUNDS_BEFORE,
             FORKSKINNY_64_192_ROUNDS_BEFORE +
             FORKSKINNY_64_192_ROUNDS_AFTER);
        be_store_word16(output_right,     state.S[0]);
        be_store_word16(output_right + 2, state.S[1]);
        be_store_word16(output_right + 4, state.S[2]);
        be_store_word16(output_right + 6, state.S[3]);

        /* Restore the state at the forking point */
        state.S[0] = F[0];
        state.S[1] = F[1];
        state.S[2] = F[2];
        state.S[3] = F[3];
    }
    if (output_left) {
        /* Generate the left output block */
        state.S[0] ^= 0x1249U;  /* Branching constant */
        state.S[1] ^= 0x36daU;
        state.S[2] ^= 0x5b7fU;
        state.S[3] ^= 0xec81U;
        forkskinny_64_192_rounds
            (&state, &tks, FORKSKINNY_64_192_ROUNDS_BEFORE +
                     FORKSKINNY_64_192_ROUNDS_AFTER,
             FORKSKINNY_64_192_ROUNDS_BEFORE +
             FORKSKINNY_64_192_ROUNDS_AFTER * 2);
        be_store_word16(output_left,     state.S[0]);
        be_store_word16(output_left + 2, state.S[1]);
        be_store_word16(output_left + 4, state.S[2]);
        be_store_word16(output_left + 6, state.S[3]);
    } else {
        /* We only need the right output block */
        forkskinny_64_192_rounds
            (&state, &tks, FORKSKINNY_64_192_ROUNDS_BEFORE,
             FORKSKINNY_64_192_ROUNDS_BEFORE +
             FORKSKINNY_64_192_ROUNDS_AFTER);
        be_store_word16(output_right,     state.S[0]);
        be_store_word16(output_right + 2, state.S[1]);
        be_store_word16(output_right + 4, state.S[2]);
        be_store_word16(output_right + 6, state.S[3]);
    }
}

void forkskinny_64_192_decrypt
    (const unsigned char key[24], unsigned char *output_left,
     unsigned char *output_right, const unsigned char *input)
{
    forkskinny_64_192_state_t state;
    forkskinny_64_192_state_t fstate;
    forkskinny_64_192_tweakey_schedule_t tks;

	/* Iterate key schedule */
	forkskinny_64_192_init_tks(&tks, key, FORKSKINNY_64_192_ROUNDS_BEFORE + 2*FORKSKINNY_64_192_ROUNDS_AFTER);

    /* Unpack the input */
    state.S[0] = be_load_word16(input);
    state.S[1] = be_load_word16(input + 2);
    state.S[2] = be_load_word16(input + 4);
    state.S[3] = be_load_word16(input + 6);

    /* Perform the "after" rounds on the input to get back
     * to the forking point in the cipher */
    forkskinny_64_192_inv_rounds
        (&state, &tks, FORKSKINNY_64_192_ROUNDS_BEFORE +
                 FORKSKINNY_64_192_ROUNDS_AFTER * 2,
         FORKSKINNY_64_192_ROUNDS_BEFORE +
         FORKSKINNY_64_192_ROUNDS_AFTER);

    /* Remove the branching constant */
    state.S[0] ^= 0x1249U;
    state.S[1] ^= 0x36daU;
    state.S[2] ^= 0x5b7fU;
    state.S[3] ^= 0xec81U;

    /* Save the state and the tweakey at the forking point */
    fstate = state;

    /* Generate the left output block after another "before" rounds */
    forkskinny_64_192_inv_rounds(&state, &tks, FORKSKINNY_64_192_ROUNDS_BEFORE, 0);
    be_store_word16(output_left,     state.S[0]);
    be_store_word16(output_left + 2, state.S[1]);
    be_store_word16(output_left + 4, state.S[2]);
    be_store_word16(output_left + 6, state.S[3]);

    /* Generate the right output block by going forward "after"
     * rounds from the forking point */
    forkskinny_64_192_rounds
        (&fstate, &tks, FORKSKINNY_64_192_ROUNDS_BEFORE,
         FORKSKINNY_64_192_ROUNDS_BEFORE +
         FORKSKINNY_64_192_ROUNDS_AFTER);
    be_store_word16(output_right,     fstate.S[0]);
    be_store_word16(output_right + 2, fstate.S[1]);
    be_store_word16(output_right + 4, fstate.S[2]);
    be_store_word16(output_right + 6, fstate.S[3]);
}
