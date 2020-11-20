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

#include "internal-forkskinny.h"
#include "internal-skinnyutil.h"

/**
 * \brief 7-bit round constants for all ForkSkinny block ciphers.
 */
static unsigned char const RC[87] = {
    0x01, 0x03, 0x07, 0x0f, 0x1f, 0x3f, 0x7e, 0x7d,
    0x7b, 0x77, 0x6f, 0x5f, 0x3e, 0x7c, 0x79, 0x73,
    0x67, 0x4f, 0x1e, 0x3d, 0x7a, 0x75, 0x6b, 0x57,
    0x2e, 0x5c, 0x38, 0x70, 0x61, 0x43, 0x06, 0x0d,
    0x1b, 0x37, 0x6e, 0x5d, 0x3a, 0x74, 0x69, 0x53,
    0x26, 0x4c, 0x18, 0x31, 0x62, 0x45, 0x0a, 0x15,
    0x2b, 0x56, 0x2c, 0x58, 0x30, 0x60, 0x41, 0x02,
    0x05, 0x0b, 0x17, 0x2f, 0x5e, 0x3c, 0x78, 0x71,
    0x63, 0x47, 0x0e, 0x1d, 0x3b, 0x76, 0x6d, 0x5b,
    0x36, 0x6c, 0x59, 0x32, 0x64, 0x49, 0x12, 0x25,
    0x4a, 0x14, 0x29, 0x52, 0x24, 0x48, 0x10
};

static const uint32_t T[256] = {0x65656565, 0x4c4c4c4c, 0x6a6a6a6a, 0x42424242, 0x4b4b4b4b, 0x63636363, 0x43434343, 0x6b6b6b6b, 0x55555555, 0x75757575, 0x5a5a5a5a, 0x7a7a7a7a, 0x53535353, 0x73737373, 0x5b5b5b5b, 0x7b7b7b7b, 0x35353535, 0x8c8c8c8c, 0x3a3a3a3a, 0x81818181, 0x89898989, 0x33333333, 0x80808080, 0x3b3b3b3b, 0x95959595, 0x25252525, 0x98989898, 0x2a2a2a2a, 0x90909090, 0x23232323, 0x99999999, 0x2b2b2b2b, 0xe5e5e5e5, 0xcccccccc, 0xe8e8e8e8, 0xc1c1c1c1, 0xc9c9c9c9, 0xe0e0e0e0, 0xc0c0c0c0, 0xe9e9e9e9, 0xd5d5d5d5, 0xf5f5f5f5, 0xd8d8d8d8, 0xf8f8f8f8, 0xd0d0d0d0, 0xf0f0f0f0, 0xd9d9d9d9, 0xf9f9f9f9, 0xa5a5a5a5, 0x1c1c1c1c, 0xa8a8a8a8, 0x12121212, 0x1b1b1b1b, 0xa0a0a0a0, 0x13131313, 0xa9a9a9a9, 0x05050505, 0xb5b5b5b5, 0x0a0a0a0a, 0xb8b8b8b8, 0x03030303, 0xb0b0b0b0, 0x0b0b0b0b, 0xb9b9b9b9, 0x32323232, 0x88888888, 0x3c3c3c3c, 0x85858585, 0x8d8d8d8d, 0x34343434, 0x84848484, 0x3d3d3d3d, 0x91919191, 0x22222222, 0x9c9c9c9c, 0x2c2c2c2c, 0x94949494, 0x24242424, 0x9d9d9d9d, 0x2d2d2d2d, 0x62626262, 0x4a4a4a4a, 0x6c6c6c6c, 0x45454545, 0x4d4d4d4d, 0x64646464, 0x44444444, 0x6d6d6d6d, 0x52525252, 0x72727272, 0x5c5c5c5c, 0x7c7c7c7c, 0x54545454, 0x74747474, 0x5d5d5d5d, 0x7d7d7d7d, 0xa1a1a1a1, 0x1a1a1a1a, 0xacacacac, 0x15151515, 0x1d1d1d1d, 0xa4a4a4a4, 0x14141414, 0xadadadad, 0x02020202, 0xb1b1b1b1, 0x0c0c0c0c, 0xbcbcbcbc, 0x04040404, 0xb4b4b4b4, 0x0d0d0d0d, 0xbdbdbdbd, 0xe1e1e1e1, 0xc8c8c8c8, 0xecececec, 0xc5c5c5c5, 0xcdcdcdcd, 0xe4e4e4e4, 0xc4c4c4c4, 0xedededed, 0xd1d1d1d1, 0xf1f1f1f1, 0xdcdcdcdc, 0xfcfcfcfc, 0xd4d4d4d4, 0xf4f4f4f4, 0xdddddddd, 0xfdfdfdfd, 0x36363636, 0x8e8e8e8e, 0x38383838, 0x82828282, 0x8b8b8b8b, 0x30303030, 0x83838383, 0x39393939, 0x96969696, 0x26262626, 0x9a9a9a9a, 0x28282828, 0x93939393, 0x20202020, 0x9b9b9b9b, 0x29292929, 0x66666666, 0x4e4e4e4e, 0x68686868, 0x41414141, 0x49494949, 0x60606060, 0x40404040, 0x69696969, 0x56565656, 0x76767676, 0x58585858, 0x78787878, 0x50505050, 0x70707070, 0x59595959, 0x79797979, 0xa6a6a6a6, 0x1e1e1e1e, 0xaaaaaaaa, 0x11111111, 0x19191919, 0xa3a3a3a3, 0x10101010, 0xabababab, 0x06060606, 0xb6b6b6b6, 0x08080808, 0xbabababa, 0x00000000, 0xb3b3b3b3, 0x09090909, 0xbbbbbbbb, 0xe6e6e6e6, 0xcececece, 0xeaeaeaea, 0xc2c2c2c2, 0xcbcbcbcb, 0xe3e3e3e3, 0xc3c3c3c3, 0xebebebeb, 0xd6d6d6d6, 0xf6f6f6f6, 0xdadadada, 0xfafafafa, 0xd3d3d3d3, 0xf3f3f3f3, 0xdbdbdbdb, 0xfbfbfbfb, 0x31313131, 0x8a8a8a8a, 0x3e3e3e3e, 0x86868686, 0x8f8f8f8f, 0x37373737, 0x87878787, 0x3f3f3f3f, 0x92929292, 0x21212121, 0x9e9e9e9e, 0x2e2e2e2e, 0x97979797, 0x27272727, 0x9f9f9f9f, 0x2f2f2f2f, 0x61616161, 0x48484848, 0x6e6e6e6e, 0x46464646, 0x4f4f4f4f, 0x67676767, 0x47474747, 0x6f6f6f6f, 0x51515151, 0x71717171, 0x5e5e5e5e, 0x7e7e7e7e, 0x57575757, 0x77777777, 0x5f5f5f5f, 0x7f7f7f7f, 0xa2a2a2a2, 0x18181818, 0xaeaeaeae, 0x16161616, 0x1f1f1f1f, 0xa7a7a7a7, 0x17171717, 0xafafafaf, 0x01010101, 0xb2b2b2b2, 0x0e0e0e0e, 0xbebebebe, 0x07070707, 0xb7b7b7b7, 0x0f0f0f0f, 0xbfbfbfbf, 0xe2e2e2e2, 0xcacacaca, 0xeeeeeeee, 0xc6c6c6c6, 0xcfcfcfcf, 0xe7e7e7e7, 0xc7c7c7c7, 0xefefefef, 0xd2d2d2d2, 0xf2f2f2f2, 0xdededede, 0xfefefefe, 0xd7d7d7d7, 0xf7f7f7f7, 0xdfdfdfdf, 0xffffffff};
static const uint32_t T_inv[256] = {0xacacacac, 0xe8e8e8e8, 0x68686868, 0x3c3c3c3c, 0x6c6c6c6c, 0x38383838, 0xa8a8a8a8, 0xecececec, 0xaaaaaaaa, 0xaeaeaeae, 0x3a3a3a3a, 0x3e3e3e3e, 0x6a6a6a6a, 0x6e6e6e6e, 0xeaeaeaea, 0xeeeeeeee, 0xa6a6a6a6, 0xa3a3a3a3, 0x33333333, 0x36363636, 0x66666666, 0x63636363, 0xe3e3e3e3, 0xe6e6e6e6, 0xe1e1e1e1, 0xa4a4a4a4, 0x61616161, 0x34343434, 0x31313131, 0x64646464, 0xa1a1a1a1, 0xe4e4e4e4, 0x8d8d8d8d, 0xc9c9c9c9, 0x49494949, 0x1d1d1d1d, 0x4d4d4d4d, 0x19191919, 0x89898989, 0xcdcdcdcd, 0x8b8b8b8b, 0x8f8f8f8f, 0x1b1b1b1b, 0x1f1f1f1f, 0x4b4b4b4b, 0x4f4f4f4f, 0xcbcbcbcb, 0xcfcfcfcf, 0x85858585, 0xc0c0c0c0, 0x40404040, 0x15151515, 0x45454545, 0x10101010, 0x80808080, 0xc5c5c5c5, 0x82828282, 0x87878787, 0x12121212, 0x17171717, 0x42424242, 0x47474747, 0xc2c2c2c2, 0xc7c7c7c7, 0x96969696, 0x93939393, 0x03030303, 0x06060606, 0x56565656, 0x53535353, 0xd3d3d3d3, 0xd6d6d6d6, 0xd1d1d1d1, 0x94949494, 0x51515151, 0x04040404, 0x01010101, 0x54545454, 0x91919191, 0xd4d4d4d4, 0x9c9c9c9c, 0xd8d8d8d8, 0x58585858, 0x0c0c0c0c, 0x5c5c5c5c, 0x08080808, 0x98989898, 0xdcdcdcdc, 0x9a9a9a9a, 0x9e9e9e9e, 0x0a0a0a0a, 0x0e0e0e0e, 0x5a5a5a5a, 0x5e5e5e5e, 0xdadadada, 0xdededede, 0x95959595, 0xd0d0d0d0, 0x50505050, 0x05050505, 0x55555555, 0x00000000, 0x90909090, 0xd5d5d5d5, 0x92929292, 0x97979797, 0x02020202, 0x07070707, 0x52525252, 0x57575757, 0xd2d2d2d2, 0xd7d7d7d7, 0x9d9d9d9d, 0xd9d9d9d9, 0x59595959, 0x0d0d0d0d, 0x5d5d5d5d, 0x09090909, 0x99999999, 0xdddddddd, 0x9b9b9b9b, 0x9f9f9f9f, 0x0b0b0b0b, 0x0f0f0f0f, 0x5b5b5b5b, 0x5f5f5f5f, 0xdbdbdbdb, 0xdfdfdfdf, 0x16161616, 0x13131313, 0x83838383, 0x86868686, 0x46464646, 0x43434343, 0xc3c3c3c3, 0xc6c6c6c6, 0x41414141, 0x14141414, 0xc1c1c1c1, 0x84848484, 0x11111111, 0x44444444, 0x81818181, 0xc4c4c4c4, 0x1c1c1c1c, 0x48484848, 0xc8c8c8c8, 0x8c8c8c8c, 0x4c4c4c4c, 0x18181818, 0x88888888, 0xcccccccc, 0x1a1a1a1a, 0x1e1e1e1e, 0x8a8a8a8a, 0x8e8e8e8e, 0x4a4a4a4a, 0x4e4e4e4e, 0xcacacaca, 0xcececece, 0x35353535, 0x60606060, 0xe0e0e0e0, 0xa5a5a5a5, 0x65656565, 0x30303030, 0xa0a0a0a0, 0xe5e5e5e5, 0x32323232, 0x37373737, 0xa2a2a2a2, 0xa7a7a7a7, 0x62626262, 0x67676767, 0xe2e2e2e2, 0xe7e7e7e7, 0x3d3d3d3d, 0x69696969, 0xe9e9e9e9, 0xadadadad, 0x6d6d6d6d, 0x39393939, 0xa9a9a9a9, 0xedededed, 0x3b3b3b3b, 0x3f3f3f3f, 0xabababab, 0xafafafaf, 0x6b6b6b6b, 0x6f6f6f6f, 0xebebebeb, 0xefefefef, 0x26262626, 0x23232323, 0xb3b3b3b3, 0xb6b6b6b6, 0x76767676, 0x73737373, 0xf3f3f3f3, 0xf6f6f6f6, 0x71717171, 0x24242424, 0xf1f1f1f1, 0xb4b4b4b4, 0x21212121, 0x74747474, 0xb1b1b1b1, 0xf4f4f4f4, 0x2c2c2c2c, 0x78787878, 0xf8f8f8f8, 0xbcbcbcbc, 0x7c7c7c7c, 0x28282828, 0xb8b8b8b8, 0xfcfcfcfc, 0x2a2a2a2a, 0x2e2e2e2e, 0xbabababa, 0xbebebebe, 0x7a7a7a7a, 0x7e7e7e7e, 0xfafafafa, 0xfefefefe, 0x25252525, 0x70707070, 0xf0f0f0f0, 0xb5b5b5b5, 0x75757575, 0x20202020, 0xb0b0b0b0, 0xf5f5f5f5, 0x22222222, 0x27272727, 0xb2b2b2b2, 0xb7b7b7b7, 0x72727272, 0x77777777, 0xf2f2f2f2, 0xf7f7f7f7, 0x2d2d2d2d, 0x79797979, 0xf9f9f9f9, 0xbdbdbdbd, 0x7d7d7d7d, 0x29292929, 0xb9b9b9b9, 0xfdfdfdfd, 0x2b2b2b2b, 0x2f2f2f2f, 0xbbbbbbbb, 0xbfbfbfbf, 0x7b7b7b7b, 0x7f7f7f7f, 0xfbfbfbfb, 0xffffffff};

static const uint32_t AC_column0[87] = {0x1000101, 0x3000303, 0x7000707, 0xf000f0f, 0xf000f0f, 0xf000f0f, 0xe000e0e, 0xd000d0d, 0xb000b0b, 0x7000707, 0xf000f0f, 0xf000f0f, 0xe000e0e, 0xc000c0c, 0x9000909, 0x3000303, 0x7000707, 0xf000f0f, 0xe000e0e, 0xd000d0d, 0xa000a0a, 0x5000505, 0xb000b0b, 0x7000707, 0xe000e0e, 0xc000c0c, 0x8000808, 0x0, 0x1000101, 0x3000303, 0x6000606, 0xd000d0d, 0xb000b0b, 0x7000707, 0xe000e0e, 0xd000d0d, 0xa000a0a, 0x4000404, 0x9000909, 0x3000303, 0x6000606, 0xc000c0c, 0x8000808, 0x1000101, 0x2000202, 0x5000505, 0xa000a0a, 0x5000505, 0xb000b0b, 0x6000606, 0xc000c0c, 0x8000808, 0x0, 0x0, 0x1000101, 0x2000202, 0x5000505, 0xb000b0b, 0x7000707, 0xf000f0f, 0xe000e0e, 0xc000c0c, 0x8000808, 0x1000101, 0x3000303, 0x7000707, 0xe000e0e, 0xd000d0d, 0xb000b0b, 0x6000606, 0xd000d0d, 0xb000b0b, 0x6000606, 0xc000c0c, 0x9000909, 0x2000202, 0x4000404, 0x9000909, 0x2000202, 0x5000505, 0xa000a0a, 0x4000404, 0x9000909, 0x2000202, 0x4000404, 0x8000808, 0x0};
static const uint32_t AC_column1[87] = {0x0, 0x0, 0x0, 0x0, 0x10000, 0x30000, 0x70000, 0x70000, 0x70000, 0x70000, 0x60000, 0x50000, 0x30000, 0x70000, 0x70000, 0x70000, 0x60000, 0x40000, 0x10000, 0x30000, 0x70000, 0x70000, 0x60000, 0x50000, 0x20000, 0x50000, 0x30000, 0x70000, 0x60000, 0x40000, 0x0, 0x0, 0x10000, 0x30000, 0x60000, 0x50000, 0x30000, 0x70000, 0x60000, 0x50000, 0x20000, 0x40000, 0x10000, 0x30000, 0x60000, 0x40000, 0x0, 0x10000, 0x20000, 0x50000, 0x20000, 0x50000, 0x30000, 0x60000, 0x40000, 0x0, 0x0, 0x0, 0x10000, 0x20000, 0x50000, 0x30000, 0x70000, 0x70000, 0x60000, 0x40000, 0x0, 0x10000, 0x30000, 0x70000, 0x60000, 0x50000, 0x30000, 0x60000, 0x50000, 0x30000, 0x60000, 0x40000, 0x10000, 0x20000, 0x40000, 0x10000, 0x20000, 0x50000, 0x20000, 0x40000, 0x10000};


#if !defined(__AVR__)

void forkskinny_128_256_rounds
    (forkskinny_128_256_state_t *state, unsigned first, unsigned last)
{
    uint32_t s0, s1, s2, s3, t0, t1, t2, t3;
    uint32_t tk_columns[4];

    /* Load the state into local variables */
    s0 = state->S[0];
    s1 = state->S[1];
    s2 = state->S[2];
    s3 = state->S[3];

    /* Perform all requested rounds */
    for (; first < last; ++first) {

        TK_to_column_256(tk_columns, state);

        t0 = (T[s0 & 0xff]&0xff00ffff) ^ (T[(s3>>8) & 0xff]&0x00ff0000) ^ (T[(s2>>16) & 0xff]&0xffff00ff) ^ (T[(s1>>24)]&0xff) ^ tk_columns[0] ^ AC_column0[first];
        t1 = (T[s1 & 0xff]&0xff00ffff) ^ (T[(s0>>8) & 0xff]&0x00ff0000) ^ (T[(s3>>16) & 0xff]&0xffff00ff) ^ (T[(s2>>24)]&0xff) ^ tk_columns[1] ^ AC_column1[first];
        t2 = (T[s2 & 0xff]&0xff00ffff) ^ (T[(s1>>8) & 0xff]&0x00ff0000) ^ (T[(s0>>16) & 0xff]&0xffff00ff) ^ (T[(s3>>24)]&0xff) ^ tk_columns[2] ^ 0x00020200;
        t3 = (T[s3 & 0xff]&0xff00ffff) ^ (T[(s2>>8) & 0xff]&0x00ff0000) ^ (T[(s1>>16) & 0xff]&0xffff00ff) ^ (T[(s0>>24)]&0xff) ^ tk_columns[3];

        /* Permute TK1 and TK2 for the next round */
        skinny128_permute_tk(state->TK1);
        skinny128_permute_tk(state->TK2);
        skinny128_LFSR2(state->TK2[0]);
        skinny128_LFSR2(state->TK2[1]);

        s0 = t0; s1 = t1; s2 = t2; s3 = t3;
    }

    /* Save the local variables back to the state */
    state->S[0] = s0;
    state->S[1] = s1;
    state->S[2] = s2;
    state->S[3] = s3;
}

void forkskinny_128_256_inv_rounds
    (forkskinny_128_256_state_t *state, unsigned first, unsigned last)
{
    uint32_t s0, s1, s2, s3, t0, t1, t2, t3, tk0, tk1;
    uint8_t rc;

    /* Load the state into local variables */
    t0 = state->S[0];
    t1 = state->S[1];
    t2 = state->S[2];
    t3 = state->S[3];

    // FIRST ROUND

    /* Permute TK1 and TK2 for the next round */
    skinny128_inv_LFSR2(state->TK2[0]);
    skinny128_inv_LFSR2(state->TK2[1]);
    skinny128_inv_permute_tk(state->TK1);
    skinny128_inv_permute_tk(state->TK2);

    /* Inverse mix of the columns */
    s0 = t0;
    t0 = t1;
    t1 = t2;
    t2 = t3;
    t3 = s0 ^ t2;
    t2 ^= t0;
    t1 ^= t2;

    /* XOR the shifted round constant and the shifted subkey for this round */
    rc = RC[--first];
    t0 ^= state->TK1[0] ^ state->TK2[0] ^ (rc & 0x0F) ^ 0x00020000;
    t1 ^= leftRotate8((state->TK1[1] ^ state->TK2[1] ^ (rc >> 4)));
    t2 ^= 0x020000;

    /* Save the local variables in temp but first convert them to columns*/
    rows_to_columns_32(s0, s1, s2, s3, t0, t1, t2, t3);


    /* Perform all requested rounds */
    while (first > last) {
        /* Permute TK1 and TK2 for the next round */
        skinny128_inv_LFSR2(state->TK2[0]);
        skinny128_inv_LFSR2(state->TK2[1]);
        skinny128_inv_permute_tk(state->TK1);
        skinny128_inv_permute_tk(state->TK2);

        t0 = (T_inv[s0 & 0xff]&0xff000000) ^ (T_inv[(s1>>8) & 0xff]&0x00ffffff) ^ (T_inv[(s2>>16) & 0xff]&0x0000ff00) ^ (T_inv[(s3>>24)]&0xffffff00);
        t1 = (T_inv[s1 & 0xff]&0xff000000) ^ (T_inv[(s2>>8) & 0xff]&0x00ffffff) ^ (T_inv[(s3>>16) & 0xff]&0x0000ff00) ^ (T_inv[(s0>>24)]&0xffffff00);
        t2 = (T_inv[s2 & 0xff]&0xff000000) ^ (T_inv[(s3>>8) & 0xff]&0x00ffffff) ^ (T_inv[(s0>>16) & 0xff]&0x0000ff00) ^ (T_inv[(s1>>24)]&0xffffff00);
        t3 = (T_inv[s3 & 0xff]&0xff000000) ^ (T_inv[(s0>>8) & 0xff]&0x00ffffff) ^ (T_inv[(s1>>16) & 0xff]&0x0000ff00) ^ (T_inv[(s2>>24)]&0xffffff00);

        /* XOR the shifted round constant and the shifted subkey for this round */
        rc = RC[--first];
        tk0 = state->TK1[0] ^ state->TK2[0] ^ (rc & 0x0F) ^ 0x00020000;
        tk1 = leftRotate8((state->TK1[1] ^ state->TK2[1] ^ (rc >> 4)));

        s0 = t0 ^ (((tk0)    &0xff) | ((tk1<<8)&0xff00));
        s1 = t1 ^ (((tk0>>8) &0xff) | ((tk1)&0xff00));
        s2 = t2 ^ (((tk0>>16)&0xff) | ((tk1>>8)&0xff00)) ^ 0x020000;
        s3 = t3 ^ (((tk0>>24)&0xff) | ((tk1>>16)&0xff00));
    }

    // FINAL ROUND

    /* Apply the inverse of the S-box to all cells in the state */
	skinny128_inv_sbox(s0);
	skinny128_inv_sbox(s1);
	skinny128_inv_sbox(s2);
	skinny128_inv_sbox(s3);

    /* Save the local variables back to the state but first convert them back to rows*/
	columns_to_rows_32(t0, t1, t2, t3, s0, s1, s2, s3);

	/* Shift the cells in the rows left, which moves the cell
	 * values down closer to the LSB.  That is, we do a right
	 * rotate on the word to rotate the cells in the word left */
    state->S[0] = t0;
	state->S[1] = rightRotate8(t1);
	state->S[2] = rightRotate16(t2);
	state->S[3] = rightRotate24(t3);
}

void forkskinny_128_256_forward_tk
    (forkskinny_128_256_state_t *state, unsigned rounds)
{
    unsigned temp;

    /* The tweak permutation repeats every 16 rounds so we can avoid
     * some skinny128_permute_tk() calls in the early stages.  During
     * the 16 rounds, the LFSR will be applied 8 times to every word */
    while (rounds >= 16) {
        for (temp = 0; temp < 8; ++temp) {
            skinny128_LFSR2(state->TK2[0]);
            skinny128_LFSR2(state->TK2[1]);
            skinny128_LFSR2(state->TK2[2]);
            skinny128_LFSR2(state->TK2[3]);
        }
        rounds -= 16;
    }

    /* Handle the left-over rounds */
    while (rounds > 0) {
        skinny128_permute_tk(state->TK1);
        skinny128_permute_tk(state->TK2);
        skinny128_LFSR2(state->TK2[0]);
        skinny128_LFSR2(state->TK2[1]);
        --rounds;
    }
}

void forkskinny_128_256_reverse_tk
    (forkskinny_128_256_state_t *state, unsigned rounds)
{
    unsigned temp;

    /* The tweak permutation repeats every 16 rounds so we can avoid
     * some skinny128_inv_permute_tk() calls in the early stages.  During
     * the 16 rounds, the LFSR will be applied 8 times to every word */
    while (rounds >= 16) {
        for (temp = 0; temp < 8; ++temp) {
            skinny128_inv_LFSR2(state->TK2[0]);
            skinny128_inv_LFSR2(state->TK2[1]);
            skinny128_inv_LFSR2(state->TK2[2]);
            skinny128_inv_LFSR2(state->TK2[3]);
        }
        rounds -= 16;
    }

    /* Handle the left-over rounds */
    while (rounds > 0) {
        skinny128_inv_LFSR2(state->TK2[0]);
        skinny128_inv_LFSR2(state->TK2[1]);
        skinny128_inv_permute_tk(state->TK1);
        skinny128_inv_permute_tk(state->TK2);
        --rounds;
    }
}

void forkskinny_128_384_rounds
    (forkskinny_128_384_state_t *state, unsigned first, unsigned last)
{
    uint32_t s0, s1, s2, s3, t0, t1, t2, t3;
    uint32_t tk_columns[4];

    /* Load the state into local variables */
    s0 = state->S[0];
    s1 = state->S[1];
    s2 = state->S[2];
    s3 = state->S[3];

    /* Perform all requested rounds */
    for (; first < last; ++first) {

        TK_to_column_384(tk_columns, state);

        t0 = (T[s0 & 0xff]&0xff00ffff) ^ (T[(s3>>8) & 0xff]&0x00ff0000) ^ (T[(s2>>16) & 0xff]&0xffff00ff) ^ (T[(s1>>24)]&0xff) ^ tk_columns[0] ^ AC_column0[first];
        t1 = (T[s1 & 0xff]&0xff00ffff) ^ (T[(s0>>8) & 0xff]&0x00ff0000) ^ (T[(s3>>16) & 0xff]&0xffff00ff) ^ (T[(s2>>24)]&0xff) ^ tk_columns[1] ^ AC_column1[first];
        t2 = (T[s2 & 0xff]&0xff00ffff) ^ (T[(s1>>8) & 0xff]&0x00ff0000) ^ (T[(s0>>16) & 0xff]&0xffff00ff) ^ (T[(s3>>24)]&0xff) ^ tk_columns[2] ^ 0x00020200;
        t3 = (T[s3 & 0xff]&0xff00ffff) ^ (T[(s2>>8) & 0xff]&0x00ff0000) ^ (T[(s1>>16) & 0xff]&0xffff00ff) ^ (T[(s0>>24)]&0xff) ^ tk_columns[3];

        /* Permute TK1, TK2, and TK3 for the next round */
        skinny128_permute_tk(state->TK1);
        skinny128_permute_tk(state->TK2);
        skinny128_permute_tk(state->TK3);
        skinny128_LFSR2(state->TK2[0]);
        skinny128_LFSR2(state->TK2[1]);
        skinny128_LFSR3(state->TK3[0]);
        skinny128_LFSR3(state->TK3[1]);

        s0 = t0; s1 = t1; s2 = t2; s3 = t3;
    }

    /* Save the local variables back to the state */
    state->S[0] = s0;
    state->S[1] = s1;
    state->S[2] = s2;
    state->S[3] = s3;
}

void forkskinny_128_384_inv_rounds
    (forkskinny_128_384_state_t *state, unsigned first, unsigned last)
{
   uint32_t s0, s1, s2, s3, t0, t1, t2, t3, tk0, tk1;
    uint8_t rc;

    /* Load the state into local variables */
    t0 = state->S[0];
    t1 = state->S[1];
    t2 = state->S[2];
    t3 = state->S[3];

    // FIRST ROUND

    /* Permute TK1 and TK2 for the next round */
    skinny128_inv_LFSR2(state->TK2[0]);
    skinny128_inv_LFSR2(state->TK2[1]);
    skinny128_inv_LFSR3(state->TK3[0]);
    skinny128_inv_LFSR3(state->TK3[1]);
    skinny128_inv_permute_tk(state->TK1);
    skinny128_inv_permute_tk(state->TK2);
    skinny128_inv_permute_tk(state->TK3);

    /* Inverse mix of the columns */
    s0 = t0;
    t0 = t1;
    t1 = t2;
    t2 = t3;
    t3 = s0 ^ t2;
    t2 ^= t0;
    t1 ^= t2;

    /* XOR the shifted round constant and the shifted subkey for this round */
    rc = RC[--first];
    t0 ^= state->TK1[0] ^ state->TK2[0] ^ state->TK3[0] ^ (rc & 0x0F) ^ 0x00020000;
    t1 ^= leftRotate8((state->TK1[1] ^ state->TK2[1] ^ state->TK3[1] ^ (rc >> 4)));
    t2 ^= 0x020000;

    /* Save the local variables in temp but first convert them to columns*/
    rows_to_columns_32(s0, s1, s2, s3, t0, t1, t2, t3);


    /* Perform all requested rounds */
    while (first > last) {
        /* Permute TK1 and TK2 for the next round */
        skinny128_inv_LFSR2(state->TK2[0]);
        skinny128_inv_LFSR2(state->TK2[1]);
        skinny128_inv_LFSR3(state->TK3[0]);
        skinny128_inv_LFSR3(state->TK3[1]);
        skinny128_inv_permute_tk(state->TK1);
        skinny128_inv_permute_tk(state->TK2);
        skinny128_inv_permute_tk(state->TK3);

        t0 = (T_inv[s0 & 0xff]&0xff000000) ^ (T_inv[(s1>>8) & 0xff]&0x00ffffff) ^ (T_inv[(s2>>16) & 0xff]&0x0000ff00) ^ (T_inv[(s3>>24)]&0xffffff00);
        t1 = (T_inv[s1 & 0xff]&0xff000000) ^ (T_inv[(s2>>8) & 0xff]&0x00ffffff) ^ (T_inv[(s3>>16) & 0xff]&0x0000ff00) ^ (T_inv[(s0>>24)]&0xffffff00);
        t2 = (T_inv[s2 & 0xff]&0xff000000) ^ (T_inv[(s3>>8) & 0xff]&0x00ffffff) ^ (T_inv[(s0>>16) & 0xff]&0x0000ff00) ^ (T_inv[(s1>>24)]&0xffffff00);
        t3 = (T_inv[s3 & 0xff]&0xff000000) ^ (T_inv[(s0>>8) & 0xff]&0x00ffffff) ^ (T_inv[(s1>>16) & 0xff]&0x0000ff00) ^ (T_inv[(s2>>24)]&0xffffff00);

        /* XOR the shifted round constant and the shifted subkey for this round */
        rc = RC[--first];
        tk0 = state->TK1[0] ^ state->TK2[0] ^ state->TK3[0] ^ (rc & 0x0F) ^ 0x00020000;
        tk1 = leftRotate8((state->TK1[1] ^ state->TK2[1] ^ state->TK3[1] ^ (rc >> 4)));

        s0 = t0 ^ (((tk0)    &0xff) | ((tk1<<8)&0xff00));
        s1 = t1 ^ (((tk0>>8) &0xff) | ((tk1)&0xff00));
        s2 = t2 ^ (((tk0>>16)&0xff) | ((tk1>>8)&0xff00)) ^ 0x020000;
        s3 = t3 ^ (((tk0>>24)&0xff) | ((tk1>>16)&0xff00));
    }

    // FINAL ROUND

    /* Apply the inverse of the S-box to all cells in the state */
	skinny128_inv_sbox(s0);
	skinny128_inv_sbox(s1);
	skinny128_inv_sbox(s2);
	skinny128_inv_sbox(s3);

    /* Save the local variables back to the state but first convert them back to rows*/
	columns_to_rows_32(t0, t1, t2, t3, s0, s1, s2, s3);

	/* Shift the cells in the rows left, which moves the cell
	 * values down closer to the LSB.  That is, we do a right
	 * rotate on the word to rotate the cells in the word left */
    state->S[0] = t0;
	state->S[1] = rightRotate8(t1);
	state->S[2] = rightRotate16(t2);
	state->S[3] = rightRotate24(t3);
}

void forkskinny_128_384_forward_tk
    (forkskinny_128_384_state_t *state, unsigned rounds)
{
    unsigned temp;

    /* The tweak permutation repeats every 16 rounds so we can avoid
     * some skinny128_permute_tk() calls in the early stages.  During
     * the 16 rounds, the LFSR will be applied 8 times to every word */
    while (rounds >= 16) {
        for (temp = 0; temp < 8; ++temp) {
            skinny128_LFSR2(state->TK2[0]);
            skinny128_LFSR2(state->TK2[1]);
            skinny128_LFSR2(state->TK2[2]);
            skinny128_LFSR2(state->TK2[3]);
            skinny128_LFSR3(state->TK3[0]);
            skinny128_LFSR3(state->TK3[1]);
            skinny128_LFSR3(state->TK3[2]);
            skinny128_LFSR3(state->TK3[3]);
        }
        rounds -= 16;
    }

    /* Handle the left-over rounds */
    while (rounds > 0) {
        skinny128_permute_tk(state->TK1);
        skinny128_permute_tk(state->TK2);
        skinny128_permute_tk(state->TK3);
        skinny128_LFSR2(state->TK2[0]);
        skinny128_LFSR2(state->TK2[1]);
        skinny128_LFSR3(state->TK3[0]);
        skinny128_LFSR3(state->TK3[1]);
        --rounds;
    }
}

void forkskinny_128_384_reverse_tk
    (forkskinny_128_384_state_t *state, unsigned rounds)
{
    unsigned temp;

    /* The tweak permutation repeats every 16 rounds so we can avoid
     * some skinny128_inv_permute_tk() calls in the early stages.  During
     * the 16 rounds, the LFSR will be applied 8 times to every word */
    while (rounds >= 16) {
        for (temp = 0; temp < 8; ++temp) {
            skinny128_inv_LFSR2(state->TK2[0]);
            skinny128_inv_LFSR2(state->TK2[1]);
            skinny128_inv_LFSR2(state->TK2[2]);
            skinny128_inv_LFSR2(state->TK2[3]);
            skinny128_inv_LFSR3(state->TK3[0]);
            skinny128_inv_LFSR3(state->TK3[1]);
            skinny128_inv_LFSR3(state->TK3[2]);
            skinny128_inv_LFSR3(state->TK3[3]);
        }
        rounds -= 16;
    }

    /* Handle the left-over rounds */
    while (rounds > 0) {
        skinny128_inv_LFSR2(state->TK2[0]);
        skinny128_inv_LFSR2(state->TK2[1]);
        skinny128_inv_LFSR3(state->TK3[0]);
        skinny128_inv_LFSR3(state->TK3[1]);
        skinny128_inv_permute_tk(state->TK1);
        skinny128_inv_permute_tk(state->TK2);
        skinny128_inv_permute_tk(state->TK3);
        --rounds;
    }
}

void forkskinny_64_192_rounds
    (forkskinny_64_192_state_t *state, unsigned first, unsigned last)
{
    uint16_t s0, s1, s2, s3, temp;
    uint8_t rc;

    /* Load the state into local variables */
    s0 = state->S[0];
    s1 = state->S[1];
    s2 = state->S[2];
    s3 = state->S[3];

    /* Perform all requested rounds */
    for (; first < last; ++first) {
        /* Apply the S-box to all cells in the state */
        skinny64_sbox(s0);
        skinny64_sbox(s1);
        skinny64_sbox(s2);
        skinny64_sbox(s3);

        /* XOR the round constant and the subkey for this round */
        rc = RC[first];
        s0 ^= state->TK1[0] ^ state->TK2[0] ^ state->TK3[0] ^
              ((rc & 0x0F) << 12) ^ 0x0020;
        s1 ^= state->TK1[1] ^ state->TK2[1] ^ state->TK3[1] ^
              ((rc & 0x70) << 8);
        s2 ^= 0x2000;

        /* Shift the cells in the rows right */
        s1 = rightRotate4_16(s1);
        s2 = rightRotate8_16(s2);
        s3 = rightRotate12_16(s3);

        /* Mix the columns */
        s1 ^= s2;
        s2 ^= s0;
        temp = s3 ^ s2;
        s3 = s2;
        s2 = s1;
        s1 = s0;
        s0 = temp;

        /* Permute TK1, TK2, and TK3 for the next round */
        skinny64_permute_tk(state->TK1);
        skinny64_permute_tk(state->TK2);
        skinny64_permute_tk(state->TK3);
        skinny64_LFSR2(state->TK2[0]);
        skinny64_LFSR2(state->TK2[1]);
        skinny64_LFSR3(state->TK3[0]);
        skinny64_LFSR3(state->TK3[1]);
    }

    /* Save the local variables back to the state */
    state->S[0] = s0;
    state->S[1] = s1;
    state->S[2] = s2;
    state->S[3] = s3;
}

void forkskinny_64_192_inv_rounds
    (forkskinny_64_192_state_t *state, unsigned first, unsigned last)
{
    uint16_t s0, s1, s2, s3, temp;
    uint8_t rc;

    /* Load the state into local variables */
    s0 = state->S[0];
    s1 = state->S[1];
    s2 = state->S[2];
    s3 = state->S[3];

    /* Perform all requested rounds */
    while (first > last) {
        /* Permute TK1, TK2, and TK3 for the next round */
        skinny64_inv_LFSR2(state->TK2[0]);
        skinny64_inv_LFSR2(state->TK2[1]);
        skinny64_inv_LFSR3(state->TK3[0]);
        skinny64_inv_LFSR3(state->TK3[1]);
        skinny64_inv_permute_tk(state->TK1);
        skinny64_inv_permute_tk(state->TK2);
        skinny64_inv_permute_tk(state->TK3);

        /* Inverse mix of the columns */
        temp = s0;
        s0 = s1;
        s1 = s2;
        s2 = s3;
        s3 = temp ^ s2;
        s2 ^= s0;
        s1 ^= s2;

        /* Shift the cells in the rows left */
        s1 = leftRotate4_16(s1);
        s2 = leftRotate8_16(s2);
        s3 = leftRotate12_16(s3);

        /* XOR the round constant and the subkey for this round */
        rc = RC[--first];
        s0 ^= state->TK1[0] ^ state->TK2[0] ^ state->TK3[0] ^
              ((rc & 0x0F) << 12) ^ 0x0020;
        s1 ^= state->TK1[1] ^ state->TK2[1] ^ state->TK3[1] ^
              ((rc & 0x70) << 8);
        s2 ^= 0x2000;

        /* Apply the inverse of the S-box to all cells in the state */
        skinny64_inv_sbox(s0);
        skinny64_inv_sbox(s1);
        skinny64_inv_sbox(s2);
        skinny64_inv_sbox(s3);
    }

    /* Save the local variables back to the state */
    state->S[0] = s0;
    state->S[1] = s1;
    state->S[2] = s2;
    state->S[3] = s3;
}

void forkskinny_64_192_forward_tk
    (forkskinny_64_192_state_t *state, unsigned rounds)
{
    unsigned temp;

    /* The tweak permutation repeats every 16 rounds so we can avoid
     * some skinny64_permute_tk() calls in the early stages.  During
     * the 16 rounds, the LFSR will be applied 8 times to every word */
    while (rounds >= 16) {
        for (temp = 0; temp < 8; ++temp) {
            skinny64_LFSR2(state->TK2[0]);
            skinny64_LFSR2(state->TK2[1]);
            skinny64_LFSR2(state->TK2[2]);
            skinny64_LFSR2(state->TK2[3]);
            skinny64_LFSR3(state->TK3[0]);
            skinny64_LFSR3(state->TK3[1]);
            skinny64_LFSR3(state->TK3[2]);
            skinny64_LFSR3(state->TK3[3]);
        }
        rounds -= 16;
    }

    /* Handle the left-over rounds */
    while (rounds > 0) {
        skinny64_permute_tk(state->TK1);
        skinny64_permute_tk(state->TK2);
        skinny64_permute_tk(state->TK3);
        skinny64_LFSR2(state->TK2[0]);
        skinny64_LFSR2(state->TK2[1]);
        skinny64_LFSR3(state->TK3[0]);
        skinny64_LFSR3(state->TK3[1]);
        --rounds;
    }
}

void forkskinny_64_192_reverse_tk
    (forkskinny_64_192_state_t *state, unsigned rounds)
{
    unsigned temp;

    /* The tweak permutation repeats every 16 rounds so we can avoid
     * some skinny64_inv_permute_tk() calls in the early stages.  During
     * the 16 rounds, the LFSR will be applied 8 times to every word */
    while (rounds >= 16) {
        for (temp = 0; temp < 8; ++temp) {
            skinny64_inv_LFSR2(state->TK2[0]);
            skinny64_inv_LFSR2(state->TK2[1]);
            skinny64_inv_LFSR2(state->TK2[2]);
            skinny64_inv_LFSR2(state->TK2[3]);
            skinny64_inv_LFSR3(state->TK3[0]);
            skinny64_inv_LFSR3(state->TK3[1]);
            skinny64_inv_LFSR3(state->TK3[2]);
            skinny64_inv_LFSR3(state->TK3[3]);
        }
        rounds -= 16;
    }

    /* Handle the left-over rounds */
    while (rounds > 0) {
        skinny64_inv_LFSR2(state->TK2[0]);
        skinny64_inv_LFSR2(state->TK2[1]);
        skinny64_inv_LFSR3(state->TK3[0]);
        skinny64_inv_LFSR3(state->TK3[1]);
        skinny64_inv_permute_tk(state->TK1);
        skinny64_inv_permute_tk(state->TK2);
        skinny64_inv_permute_tk(state->TK3);
        --rounds;
    }
}

#endif /* !__AVR__ */
