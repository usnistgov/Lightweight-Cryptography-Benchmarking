/*
  ===============================================================================

 Copyright (c) 2019, CryptoExperts and PQShield Ltd.
 
 All rights reserved. A copyright license for redistribution and use in
 source and binary forms, with or without modification, is hereby granted for
 non-commercial, experimental, research, public review and evaluation
 purposes, provided that the following conditions are met:
 
 * Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

 * Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 POSSIBILITY OF SUCH DAMAGE.

  Authors: Dahmun Goudarzi, Matthieu Rivain

  ===============================================================================
*/

#include <stdint.h>
#include "api.h"


//==============================================================================
//=== Definitions
//==============================================================================

#define STATE_SIZE_96        3
#define STATE_SIZE_128       4

#define NB_ROUNDS_96        14
#define NB_ROUNDS_128       14
#define NB_ROUNDS_KS        14

#define WITH_CONST_ADD       0
#define WOUT_CONST_ADD       1

//==============================================================================
//=== Macros
//==============================================================================

#define right_rotate(row)			\
  row = (row >> 1) | (row << 31);

#define left_rotate(row,n)			\
  row = (row >> n) | (row << (32-n));

//==============================================================================
//=== Constants
//==============================================================================

#define COL_M0        0xa3861085
#define COL_M1        0x63417021
#define COL_M2        0x692cf280
#define COL_M3        0x48a54813
#define COL_MK        0xb881b9ca

#define COL_INV_M0    0x2037a121
#define COL_INV_M1    0x108ff2a0 
#define COL_INV_M2    0x9054d8c0 
#define COL_INV_M3    0x3354b117

#define KS_CONSTANT_0   0x00000080
#define KS_CONSTANT_1   0x00006a00
#define KS_CONSTANT_2   0x003f0000
#define KS_CONSTANT_3   0x24000000

#define KS_ROT_GAP1            8
#define KS_ROT_GAP2           15
#define KS_ROT_GAP3           18

//==============================================================================
//=== Declarations (assembly functions)
//==============================================================================

uint32_t mat_mult(uint32_t mat_col, uint32_t vec);

void isw_mult_96 (uint32_t state[MASKING_ORDER][STATE_SIZE_96],  int acc, int op1, int op2);
void isw_mult_128(uint32_t state[MASKING_ORDER][STATE_SIZE_128], int acc, int op1, int op2);

void isw_macc_96_201(uint32_t state[MASKING_ORDER][STATE_SIZE_96]);
void isw_macc_96_012(uint32_t state[MASKING_ORDER][STATE_SIZE_96]);
void isw_macc_96_102(uint32_t state[MASKING_ORDER][STATE_SIZE_96]);

void isw_macc_128_301(uint32_t state[MASKING_ORDER][STATE_SIZE_128]);
void isw_macc_128_012(uint32_t state[MASKING_ORDER][STATE_SIZE_128]);
void isw_macc_128_123(uint32_t state[MASKING_ORDER][STATE_SIZE_128]);
void isw_macc_128_203(uint32_t state[MASKING_ORDER][STATE_SIZE_128]);

//==============================================================================
//=== Common functions
//==============================================================================

void load_state(const uint8_t *plaintext, uint32_t *state, int state_size)
{
    int i;

    for (i=0; i<state_size; i++)
    {
        state[i] =                   plaintext[4*i+0];
        state[i] = (state[i] << 8) | plaintext[4*i+1];
        state[i] = (state[i] << 8) | plaintext[4*i+2];
        state[i] = (state[i] << 8) | plaintext[4*i+3];
    }
}

void unload_state(uint8_t *ciphertext, const uint32_t *state, int state_size)
{
    int i;

    for (i=0; i<state_size; i++)
    {
        ciphertext [4*i+0] = (uint8_t) (state[i] >> 24);
        ciphertext [4*i+1] = (uint8_t) (state[i] >> 16);
        ciphertext [4*i+2] = (uint8_t) (state[i] >>  8);
        ciphertext [4*i+3] = (uint8_t) (state[i] >>  0);
    }
}

//==============================================================================
//=== Masking functions
//==============================================================================

void mask_state_96(uint32_t state[MASKING_ORDER][STATE_SIZE_96])
{
    int i,j;

    for (i=1; i<MASKING_ORDER; i++)
    {
        for (j=0; j<STATE_SIZE_96; j++)
        {
            state[i][j] = get_random();
            state[0][j] ^= state[i][j];
        }
    }
}

void unmask_state_96(uint32_t state[MASKING_ORDER][STATE_SIZE_96])
{
    int i,j;

    for (i=1; i<MASKING_ORDER; i++)
    {
        for (j=0; j<STATE_SIZE_96; j++)
        {
            state[0][j] ^= state[i][j];
            state[i][j]  = 0;
        }
    }
}

void mask_state_128(uint32_t state[MASKING_ORDER][STATE_SIZE_128])
{
    int i,j;

    for (i=1; i<MASKING_ORDER; i++)
    {
        for (j=0; j<STATE_SIZE_128; j++)
        {
            state[i][j] = get_random();
            state[0][j] ^= state[i][j];
        }
    }
}

void unmask_state_128(uint32_t state[MASKING_ORDER][STATE_SIZE_128])
{
    int i,j;

    for (i=1; i<MASKING_ORDER; i++)
    {
        for (j=0; j<STATE_SIZE_128; j++)
        {
            state[0][j] ^= state[i][j];
            state[i][j]  = 0;
        }
    }
}

//==============================================================================
//=== Key schedule
//==============================================================================


void ks_mix_comlumns(const uint32_t *ks_prev, uint32_t *ks_next)
{
    uint32_t tmp;

    tmp = ks_prev[0] ^ ks_prev[1] ^ ks_prev[2] ^ ks_prev[3];

    ks_next[0] = ks_prev[0] ^ tmp;
    ks_next[1] = ks_prev[1] ^ tmp;
    ks_next[2] = ks_prev[2] ^ tmp;
    ks_next[3] = ks_prev[3] ^ tmp;
}

void ks_mix_rotate_rows(uint32_t *ks_state)
{
    ks_state[0] = mat_mult(COL_MK, ks_state[0]);
    left_rotate(ks_state[1],KS_ROT_GAP1)
    left_rotate(ks_state[2],KS_ROT_GAP2)
    left_rotate(ks_state[3],KS_ROT_GAP3)
}

void ks_add_constant(uint32_t *ks_state, const uint32_t ctr)
{
    ks_state[0] ^= KS_CONSTANT_0 ^ ctr;
    ks_state[1] ^= KS_CONSTANT_1;
    ks_state[2] ^= KS_CONSTANT_2;
    ks_state[3] ^= KS_CONSTANT_3;
}

void key_schedule(uint32_t* ks_state, uint8_t mode)
{
    int r;

    for (r=0; r<NB_ROUNDS_KS; r++)
    {
        ks_state += 4;

        ks_mix_comlumns(ks_state-4, ks_state);
        ks_mix_rotate_rows(ks_state);

        if (mode == WITH_CONST_ADD)
        {
            ks_add_constant(ks_state,r);    
        }
    }    
}

//==============================================================================
//=== Pyjamask-96 (encryption)
//==============================================================================

void mix_rows_96(uint32_t *state)
{
    state[0] = mat_mult(COL_M0, state[0]);
    state[1] = mat_mult(COL_M1, state[1]);
    state[2] = mat_mult(COL_M2, state[2]);
}

void add_round_key_96(uint32_t *state, const uint32_t *round_key, int r)
{
    state[0] ^= round_key[4*r+0];
    state[1] ^= round_key[4*r+1];
    state[2] ^= round_key[4*r+2];
}


void masked_sub_bytes_96(uint32_t state[MASKING_ORDER][STATE_SIZE_96])
{
    int i;

    for (i=0; i<MASKING_ORDER; i++)
    {
        state[i][0] ^= state[i][1];
        state[i][1] ^= state[i][2];
    }

    isw_macc_96_201(state);
    isw_macc_96_012(state);
    isw_macc_96_102(state);

    for (i=0; i<MASKING_ORDER; i++)
    {
        state[i][2] ^= state[i][0];
        state[i][0] ^= state[i][1];

        // swap state[i][0] <-> state[i][1]
        state[i][0] ^= state[i][1];
        state[i][1] ^= state[i][0];
        state[i][0] ^= state[i][1];
    }

    state[0][2] = ~state[0][2];
}

void masked_pyjamask_96_enc(const uint8_t *plaintext, const uint8_t masked_key[MASKING_ORDER][16], uint8_t *ciphertext)
{
    int i, r;
    
    uint32_t state[MASKING_ORDER][STATE_SIZE_96];
    uint32_t round_keys[MASKING_ORDER][4*(NB_ROUNDS_KS+1)];

    // Load masked key

    for (i=0; i<MASKING_ORDER; i++)
    {
        load_state(masked_key[i], round_keys[i], 4); 
    }

    // Key schedule

    key_schedule(round_keys[0], WITH_CONST_ADD);

    for (i=1; i<MASKING_ORDER; i++)
    {
        key_schedule(round_keys[i], WOUT_CONST_ADD);
    }

    // Load and mask state

    load_state(plaintext, state[0], STATE_SIZE_96);
    mask_state_96(state);

    // Initial AddRoundKey

    for (i=0; i<MASKING_ORDER; i++)
    {
        add_round_key_96(state[i], round_keys[i], 0); 
    }

    // Main loop

    for (r=1; r<=NB_ROUNDS_96; r++)
    {
        masked_sub_bytes_96(state);

        for (i=0; i<MASKING_ORDER; i++)
        {
            mix_rows_96(state[i]);
            add_round_key_96(state[i], round_keys[i], r); 
        }
    }

    // Unmask and unload state 

    unmask_state_96(state);
    unload_state(ciphertext, state[0], STATE_SIZE_96);
}

//==============================================================================
//=== Pyjamask-96 (decryption)
//==============================================================================

void inv_mix_rows_96(uint32_t *state)
{
    state[0] = mat_mult(COL_INV_M0, state[0]);
    state[1] = mat_mult(COL_INV_M1, state[1]);
    state[2] = mat_mult(COL_INV_M2, state[2]);
}


void masked_inv_sub_bytes_96(uint32_t state[MASKING_ORDER][STATE_SIZE_96])
{
    int i;

    state[0][2] = ~state[0][2];

    for (i=0; i<MASKING_ORDER; i++)
    {
        // swap state[i][0] <-> state[i][1]
        state[i][0] ^= state[i][1];
        state[i][1] ^= state[i][0];
        state[i][0] ^= state[i][1];

        state[i][0] ^= state[i][1];
        state[i][2] ^= state[i][0];
    }

    isw_macc_96_102(state);
    isw_macc_96_012(state);
    isw_macc_96_201(state);
    
    for (i=0; i<MASKING_ORDER; i++)
    {
        state[i][1] ^= state[i][2];
        state[i][0] ^= state[i][1];
    }
}

void masked_pyjamask_96_dec(const uint8_t *ciphertext, const uint8_t masked_key[MASKING_ORDER][16], uint8_t *plaintext)
{
    int i, r;

    uint32_t state[MASKING_ORDER][STATE_SIZE_96];
    uint32_t round_keys[MASKING_ORDER][4*(NB_ROUNDS_KS+1)];

    // Load masked key

    for (i=0; i<MASKING_ORDER; i++)
    {
        load_state(masked_key[i], round_keys[i], 4); 
    }

    // Key schedule

    key_schedule(round_keys[0], WITH_CONST_ADD);

    for (i=1; i<MASKING_ORDER; i++)
    {
        key_schedule(round_keys[i], WOUT_CONST_ADD);
    }

    // Load and mask state

    load_state(ciphertext, state[0], STATE_SIZE_96);
    mask_state_96(state);

    // Main loop

    for (r=NB_ROUNDS_96; r>0; r--)
    {
        for (i=0; i<MASKING_ORDER; i++)
        {
            add_round_key_96(state[i], round_keys[i], r); 
            inv_mix_rows_96(state[i]);
        }

        masked_inv_sub_bytes_96(state);
    }

    // Final AddRoundKey

    for (i=0; i<MASKING_ORDER; i++)
    {
        add_round_key_96(state[i], round_keys[i], 0); 
    }

    // Unmask and unload state 

    unmask_state_96(state);
    unload_state(plaintext, state[0], STATE_SIZE_96);
}



//==============================================================================
//=== Pyjamask-128 (encryption)
//==============================================================================

void mix_rows_128(uint32_t *state)
{
    state[0] = mat_mult(COL_M0, state[0]);
    state[1] = mat_mult(COL_M1, state[1]);
    state[2] = mat_mult(COL_M2, state[2]);
    state[3] = mat_mult(COL_M3, state[3]);
}

void add_round_key_128(uint32_t *state, const uint32_t *round_key, int r)
{
    state[0] ^= round_key[4*r+0];
    state[1] ^= round_key[4*r+1];
    state[2] ^= round_key[4*r+2];
    state[3] ^= round_key[4*r+3];
}

void masked_sub_bytes_128(uint32_t state[MASKING_ORDER][STATE_SIZE_128])
{
    int i;

    for (i=0; i<MASKING_ORDER; i++)
    {
        state[i][0] ^= state[i][3];
    }

    isw_macc_128_301(state);
    isw_macc_128_012(state);
    isw_macc_128_123(state);
    isw_macc_128_203(state);

    for (i=0; i<MASKING_ORDER; i++)
    {
        state[i][2] ^= state[i][1];
        state[i][1] ^= state[i][0];

        // swap state[i][2] <-> state[i][3]
        state[i][2] ^= state[i][3];
        state[i][3] ^= state[i][2];
        state[i][2] ^= state[i][3];
    }

    state[0][2] = ~state[0][2];
}

void masked_pyjamask_128_enc(const uint8_t *plaintext, const uint8_t masked_key[MASKING_ORDER][16], uint8_t *ciphertext)
{
    int i, r;
    
    uint32_t state[MASKING_ORDER][STATE_SIZE_128];
    uint32_t round_keys[MASKING_ORDER][4*(NB_ROUNDS_KS+1)];

    // Load masked key

    for (i=0; i<MASKING_ORDER; i++)
    {
        load_state(masked_key[i], round_keys[i], 4); 
    }

    // Key schedule

    key_schedule(round_keys[0], WITH_CONST_ADD);

    for (i=1; i<MASKING_ORDER; i++)
    {
        key_schedule(round_keys[i], WOUT_CONST_ADD);
    }

    // Load and mask state

    load_state(plaintext, state[0], STATE_SIZE_128);
    mask_state_128(state);

    // Initial AddRoundKey

    for (i=0; i<MASKING_ORDER; i++)
    {
        add_round_key_128(state[i], round_keys[i], 0); 
    }

    // Main loop

    for (r=1; r<=NB_ROUNDS_128; r++)
    {
        masked_sub_bytes_128(state);

        for (i=0; i<MASKING_ORDER; i++)
        {
            mix_rows_128(state[i]);
            add_round_key_128(state[i], round_keys[i], r); 
        }
    }

    // Unmask and unload state 

    unmask_state_128(state);
    unload_state(ciphertext, state[0], STATE_SIZE_128);
}

//==============================================================================
//=== Pyjamask-128 (decryption)
//==============================================================================

void inv_mix_rows_128(uint32_t *state)
{
    state[0] = mat_mult(COL_INV_M0, state[0]);
    state[1] = mat_mult(COL_INV_M1, state[1]);
    state[2] = mat_mult(COL_INV_M2, state[2]);
    state[3] = mat_mult(COL_INV_M3, state[3]);
}

void masked_inv_sub_bytes_128(uint32_t state[MASKING_ORDER][STATE_SIZE_128])
{
    int i;

    state[0][2] = ~state[0][2];

    for (i=0; i<MASKING_ORDER; i++)
    {
        // swap state[i][2] <-> state[i][3]
        state[i][2] ^= state[i][3];
        state[i][3] ^= state[i][2];
        state[i][2] ^= state[i][3];

        state[i][1] ^= state[i][0];
        state[i][2] ^= state[i][1];
    }

    isw_macc_128_203(state);
    isw_macc_128_123(state);
    isw_macc_128_012(state);
    isw_macc_128_301(state);

    for (i=0; i<MASKING_ORDER; i++)
    {
        state[i][0] ^= state[i][3];
    }
}

void masked_pyjamask_128_dec(const uint8_t *ciphertext, const uint8_t masked_key[MASKING_ORDER][16], uint8_t *plaintext)
{
    int i, r;

    uint32_t state[MASKING_ORDER][STATE_SIZE_128];
    uint32_t round_keys[MASKING_ORDER][4*(NB_ROUNDS_KS+1)];

    // Load masked key

    for (i=0; i<MASKING_ORDER; i++)
    {
        load_state(masked_key[i], round_keys[i], 4); 
    }

    // Key schedule

    key_schedule(round_keys[0], WITH_CONST_ADD);

    for (i=1; i<MASKING_ORDER; i++)
    {
        key_schedule(round_keys[i], WOUT_CONST_ADD);
    }

    // Load and mask state

    load_state(ciphertext, state[0], STATE_SIZE_128);
    mask_state_128(state);

    // Main loop

    for (r=NB_ROUNDS_128; r>0; r--)
    {
        for (i=0; i<MASKING_ORDER; i++)
        {
            add_round_key_128(state[i], round_keys[i], r); 
            inv_mix_rows_128(state[i]);
        }

        masked_inv_sub_bytes_128(state);
    }

    // Final AddRoundKey

    for (i=0; i<MASKING_ORDER; i++)
    {
        add_round_key_128(state[i], round_keys[i], 0); 
    }

    // Unmask and unload state 

    unmask_state_128(state);
    unload_state(plaintext, state[0], STATE_SIZE_128);
}

