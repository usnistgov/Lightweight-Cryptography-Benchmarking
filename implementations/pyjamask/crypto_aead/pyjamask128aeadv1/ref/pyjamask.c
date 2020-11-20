/*
===============================================================================

    Reference implementation of Pyjamask block ciphers in C
    
    Copyright (C) 2019  Dahmun Goudarzi, Jérémy Jean, Stefan Kölbl, 
    Thomas Peyrin, Matthieu Rivain, Yu Sasaki, Siang Meng Sim

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.

===============================================================================
 */

#include <stdint.h>

//==============================================================================
//=== Parameters
//==============================================================================

#define STATE_SIZE_96        3
#define STATE_SIZE_128       4

#define NB_ROUNDS_96        14
#define NB_ROUNDS_128       14
#define NB_ROUNDS_KS        14

//==============================================================================
//=== Macros
//==============================================================================

#define right_rotate(row) \
    row = (row >> 1) | (row << 31);

#define left_rotate(row,n) \
    row = (row >> n) | (row << (32-n));

//==============================================================================
//=== Constants
//==============================================================================

#define COL_M0          0xa3861085
#define COL_M1          0x63417021
#define COL_M2          0x692cf280
#define COL_M3          0x48a54813
#define COL_MK          0xb881b9ca

#define COL_INV_M0      0x2037a121
#define COL_INV_M1      0x108ff2a0 
#define COL_INV_M2      0x9054d8c0 
#define COL_INV_M3      0x3354b117

#define KS_CONSTANT_0   0x00000080
#define KS_CONSTANT_1   0x00006a00
#define KS_CONSTANT_2   0x003f0000
#define KS_CONSTANT_3   0x24000000

#define KS_ROT_GAP1      8
#define KS_ROT_GAP2     15
#define KS_ROT_GAP3     18

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

uint32_t mat_mult(uint32_t mat_col, uint32_t vec)
{
    int i;
    uint32_t mask, res=0;

    for (i = 31; i>=0; i--)
    {
        mask = -((vec >> i) & 1);
        res ^= mask & mat_col;
        right_rotate(mat_col);
    }

    return res;
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

void key_schedule(const uint8_t *key, uint32_t* round_keys)
{
    int r;
    uint32_t *ks_state = round_keys;

    load_state(key, ks_state, 4); 

    for (r=0; r<NB_ROUNDS_KS; r++)
    {
        ks_state += 4;

        ks_mix_comlumns(ks_state-4, ks_state);
        ks_mix_rotate_rows(ks_state);
        ks_add_constant(ks_state,r);

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

void sub_bytes_96(uint32_t *state)
{
    state[0] ^= state[1];
    state[1] ^= state[2];
    state[2] ^= state[0] & state[1];
    state[0] ^= state[1] & state[2];
    state[1] ^= state[0] & state[2];
    state[2] ^= state[0];
    state[0] ^= state[1];
    state[2] = ~state[2];

    // swap state[0] <-> state[1]
    state[0] ^= state[1];
    state[1] ^= state[0];
    state[0] ^= state[1];
}

void add_round_key_96(uint32_t *state, const uint32_t *round_key, int r)
{
    state[0] ^= round_key[4*r+0];
    state[1] ^= round_key[4*r+1];
    state[2] ^= round_key[4*r+2];
}

void pyjamask_96_enc(const uint8_t *plaintext, const uint8_t *key, uint8_t *ciphertext)
{
    int r;
    uint32_t state[STATE_SIZE_96];
    uint32_t round_keys[4*(NB_ROUNDS_KS+1)];

    key_schedule(key, round_keys);
    load_state(plaintext, state, STATE_SIZE_96);

    for (r=0; r<NB_ROUNDS_96; r++)
    {
        add_round_key_96(state, round_keys, r); 
        sub_bytes_96(state);
        mix_rows_96(state);
    }

    add_round_key_96(state, round_keys, NB_ROUNDS_96);

    unload_state(ciphertext, state, STATE_SIZE_96);
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

void inv_sub_bytes_96(uint32_t *state)
{
    // swap state[0] <-> state[1]
    state[0] ^= state[1];
    state[1] ^= state[0];
    state[0] ^= state[1];

    state[2] = ~state[2];
    state[0] ^= state[1];
    state[2] ^= state[0];
    state[1] ^= state[2] & state[0];
    state[0] ^= state[1] & state[2];
    state[2] ^= state[0] & state[1];
    state[1] ^= state[2];
    state[0] ^= state[1];
}

void pyjamask_96_dec(const uint8_t *ciphertext, const uint8_t *key, uint8_t *plaintext)
{
    int r;
    uint32_t state[STATE_SIZE_96];
    uint32_t round_keys[4*(NB_ROUNDS_KS+1)];

    key_schedule(key, round_keys);
    load_state(ciphertext, state, STATE_SIZE_96);

    add_round_key_96(state, round_keys, NB_ROUNDS_96);

    for (r=NB_ROUNDS_96-1; r>=0; r--)
    {
        inv_mix_rows_96(state);
        inv_sub_bytes_96(state);
        add_round_key_96(state, round_keys, r);
    }

    unload_state(plaintext, state, STATE_SIZE_96);
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

void sub_bytes_128(uint32_t *state)
{
    state[0] ^= state[3];
    state[3] ^= state[0] & state[1];
    state[0] ^= state[1] & state[2];
    state[1] ^= state[2] & state[3];
    state[2] ^= state[0] & state[3];
    state[2] ^= state[1];
    state[1] ^= state[0];
    state[3] = ~state[3];

    // swap state[2] <-> state[3]
    state[2] ^= state[3];
    state[3] ^= state[2];
    state[2] ^= state[3];
}

void add_round_key_128(uint32_t *state, const uint32_t *round_key, int r)
{
    state[0] ^= round_key[4*r+0];
    state[1] ^= round_key[4*r+1];
    state[2] ^= round_key[4*r+2];
    state[3] ^= round_key[4*r+3];
}

void pyjamask_128_enc(const uint8_t *plaintext, const uint8_t *key, uint8_t *ciphertext)
{
    int r;
    uint32_t state[STATE_SIZE_128];
    uint32_t round_keys[4*(NB_ROUNDS_KS+1)];

    key_schedule(key, round_keys);
    load_state(plaintext, state, STATE_SIZE_128);


    for (r=0; r<NB_ROUNDS_128; r++)
    {
        add_round_key_128(state, round_keys, r);
        sub_bytes_128(state);
        mix_rows_128(state);
    }

    add_round_key_128(state, round_keys, NB_ROUNDS_128);
    
    unload_state(ciphertext, state, STATE_SIZE_128);
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

void inv_sub_bytes_128(uint32_t *state)
{
    // swap state[2] <-> state[3]
    state[2] ^= state[3];
    state[3] ^= state[2];
    state[2] ^= state[3];

    state[3] = ~state[3];
    state[1] ^= state[0];
    state[2] ^= state[1];
    state[2] ^= state[3] & state[0];
    state[1] ^= state[2] & state[3];
    state[0] ^= state[1] & state[2];
    state[3] ^= state[0] & state[1];
    state[0] ^= state[3];
}

void pyjamask_128_dec(const uint8_t *ciphertext, const uint8_t *key, uint8_t *plaintext)
{
    int r;
    uint32_t state[STATE_SIZE_128];
    uint32_t round_keys[4*(NB_ROUNDS_KS+1)];

    key_schedule(key, round_keys);
    load_state(ciphertext, state, STATE_SIZE_128);

    add_round_key_128(state, round_keys, NB_ROUNDS_128);
    
    for (r=NB_ROUNDS_128-1; r>=0; r--)
    {
        inv_mix_rows_128(state);
        inv_sub_bytes_128(state);
        add_round_key_128(state, round_keys, r);
    }

    unload_state(plaintext, state, STATE_SIZE_128);
}


