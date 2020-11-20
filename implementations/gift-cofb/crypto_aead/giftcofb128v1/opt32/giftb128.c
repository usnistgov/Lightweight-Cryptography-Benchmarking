/*******************************************************************************
* Optimized constant-time implementation of the GIFTb-128 block cipher.
* 
* @author   Alexandre Adomnicai, Nanyang Technological University,
*           alexandre.adomnicai@ntu.edu.sg
*
* @date     January 2020
*******************************************************************************/
#include "endian.h"
#include "giftb128.h"
#include "key_schedule.h"

/*****************************************************************************
* The round constants according to the fixsliced representation.
*****************************************************************************/
const u32 rconst[40] = {
    0x10000008, 0x80018000, 0x54000002, 0x01010181,
    0x8000001f, 0x10888880, 0x6001e000, 0x51500002,
    0x03030180, 0x8000002f, 0x10088880, 0x60016000,
    0x41500002, 0x03030080, 0x80000027, 0x10008880,
    0x4001e000, 0x11500002, 0x03020180, 0x8000002b,
    0x10080880, 0x60014000, 0x01400002, 0x02020080,
    0x80000021, 0x10000080, 0x0001c000, 0x51000002,
    0x03010180, 0x8000002e, 0x10088800, 0x60012000,
    0x40500002, 0x01030080, 0x80000006, 0x10008808,
    0xc001a000, 0x14500002, 0x01020181, 0x8000001a
};

/*****************************************************************************
* The first 20 rkeys are computed using the classical representation before
* being rearranged into fixsliced representations depending on round numbers.
* The 60 remaining rkeys are directly computed in fixscliced representations.
*****************************************************************************/
void precompute_rkeys(u32* rkey, const u8* key) {
    u32 tmp;
    //classical initialization
    rkey[0] = U32BIG(((u32*)key)[3]);
    rkey[1] = U32BIG(((u32*)key)[1]);
    rkey[2] = U32BIG(((u32*)key)[2]);
    rkey[3] = U32BIG(((u32*)key)[0]);
    // classical keyschedule
    for(int i = 0; i < 16; i+=2) {
        rkey[i+4] = rkey[i+1];
        rkey[i+5] = KEY_UPDATE(rkey[i]);
    }
    // transposition to fixsliced representations
    for(int i = 0; i < 20; i+=10) {
        rkey[i] = REARRANGE_RKEY_0(rkey[i]);
        rkey[i + 1] = REARRANGE_RKEY_0(rkey[i + 1]);
        rkey[i + 2] = REARRANGE_RKEY_1(rkey[i + 2]);
        rkey[i + 3] = REARRANGE_RKEY_1(rkey[i + 3]);
        rkey[i + 4] = REARRANGE_RKEY_2(rkey[i + 4]);
        rkey[i + 5] = REARRANGE_RKEY_2(rkey[i + 5]);
        rkey[i + 6] = REARRANGE_RKEY_3(rkey[i + 6]);
        rkey[i + 7] = REARRANGE_RKEY_3(rkey[i + 7]);
    }
    // keyschedule according to fixsliced representations
    for(int i = 20; i < 80; i+=10) {
        rkey[i] = rkey[i-19];
        rkey[i+1] = KEY_TRIPLE_UPDATE_0(rkey[i-20]);
        rkey[i+2] = KEY_DOUBLE_UPDATE_1(rkey[i-17]);
        rkey[i+3] = KEY_TRIPLE_UPDATE_1(rkey[i-18]);
        rkey[i+4] = KEY_DOUBLE_UPDATE_2(rkey[i-15]);
        rkey[i+5] = KEY_TRIPLE_UPDATE_2(rkey[i-16]);
        rkey[i+6] = KEY_DOUBLE_UPDATE_3(rkey[i-13]);
        rkey[i+7] = KEY_TRIPLE_UPDATE_3(rkey[i-14]);
        rkey[i+8] = KEY_DOUBLE_UPDATE_4(rkey[i-11]);
        rkey[i+9] = KEY_TRIPLE_UPDATE_4(rkey[i-12]);
        SWAPMOVE(rkey[i], rkey[i], 0x00003333, 16);
        SWAPMOVE(rkey[i], rkey[i], 0x55554444, 1);
        SWAPMOVE(rkey[i+1], rkey[i+1], 0x55551100, 1);
    }
}

/*****************************************************************************
* Encryption of a single 128-bit block with GIFTb-128 (used in GIFT-COFB).
*****************************************************************************/
void giftb128(u8* ctext, const u8* ptext, const u32* rkey) {
    u32 tmp, state[4];
    state[0] = U32BIG(((u32*)ptext)[0]);
    state[1] = U32BIG(((u32*)ptext)[1]);
    state[2] = U32BIG(((u32*)ptext)[2]);
    state[3] = U32BIG(((u32*)ptext)[3]);
    QUINTUPLE_ROUND(state, rkey, rconst);
    QUINTUPLE_ROUND(state, rkey + 10, rconst + 5);
    QUINTUPLE_ROUND(state, rkey + 20, rconst + 10);
    QUINTUPLE_ROUND(state, rkey + 30, rconst + 15);
    QUINTUPLE_ROUND(state, rkey + 40, rconst + 20);
    QUINTUPLE_ROUND(state, rkey + 50, rconst + 25);
    QUINTUPLE_ROUND(state, rkey + 60, rconst + 30);
    QUINTUPLE_ROUND(state, rkey + 70, rconst + 35);
    U8BIG(ctext, state[0]);
    U8BIG(ctext + 4, state[1]);
    U8BIG(ctext + 8, state[2]);
    U8BIG(ctext + 12, state[3]);
}
