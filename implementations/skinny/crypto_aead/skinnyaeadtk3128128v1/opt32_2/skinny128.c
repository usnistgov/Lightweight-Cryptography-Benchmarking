/******************************************************************************
* Fixsliced implementation of SKINNY-128-384.
* Two blocks are processed in parallel.
*
* This implementation doesn't compute the ShiftRows operation. Some masks and
* shifts are applied during the MixColumns operation so that the proper bits
* are XORed together. Moreover, the row permutation within the MixColumns 
* is omitted, as well as the bit permutation at the end of the Sbox. The rows
* are synchronized with the classical after only 4 rounds. However, the Sbox
* permutation requires 8 rounds for a synchronization. To limit the impact
* on code size, we compute the permutation every 4 rounds. Therefore, this
* implementation relies on a "QUADRUPLE_ROUND" routine.
*
* For more details, see the paper at: https://
*
* @author	Alexandre Adomnicai, Nanyang Technological University,
*			alexandre.adomnicai@ntu.edu.sg
*
* @date		June 2020
******************************************************************************/
#include "skinny128.h"

/****************************************************************************
* The MixColumns operation for rounds i such that (i % 4) == 0.
****************************************************************************/
void mixcolumns_0(u32* state) {
	u32 tmp;
	for(int i = 0; i < 8; i++) {
		tmp = ROR(state[i],24) & 0x0c0c0c0c;
		state[i] ^= ROR(tmp,30);
		tmp = ROR(state[i],16) & 0xc0c0c0c0;
		state[i] ^= ROR(tmp,4);
		tmp = ROR(state[i],8) & 0x0c0c0c0c;
		state[i] ^= ROR(tmp,2);
	}
}

/****************************************************************************
* The MixColumns operation for rounds i such that (i % 4) == 1.
****************************************************************************/
void mixcolumns_1(u32* state) {
	u32 tmp;
	for(int i = 0; i < 8; i++) {
		tmp = ROR(state[i],16) & 0x30303030;
		state[i] ^= ROR(tmp,30);
		tmp = state[i] & 0x03030303;
		state[i] ^= ROR(tmp,28);
		tmp = ROR(state[i],16) & 0x30303030;
		state[i] ^= ROR(tmp,2);
	}
}

/****************************************************************************
* The MixColumns operation for rounds i such that (i % 4) == 2.
****************************************************************************/
void mixcolumns_2(u32* state) {
	u32 tmp;
	for(int i = 0; i < 8; i++) {
		tmp = ROR(state[i],8) & 0xc0c0c0c0;
		state[i] ^= ROR(tmp,6);
		tmp = ROR(state[i],16) & 0x0c0c0c0c;
		state[i] ^= ROR(tmp,28);
		tmp = ROR(state[i],24) & 0xc0c0c0c0;
		state[i] ^= ROR(tmp,2);
	}
}

/****************************************************************************
* The MixColumns operation for rounds i such that (i % 4) == 3.
****************************************************************************/
void mixcolumns_3(u32* state) {
	u32 tmp;
	for(int i = 0; i < 8; i++) {
		tmp = state[i] & 0x03030303;
		state[i] ^= ROR(tmp,30);
		tmp = state[i] & 0x30303030;
		state[i] ^= ROR(tmp,4);
		tmp = state[i] & 0x03030303;
		state[i] ^= ROR(tmp,26);
	}
}

/****************************************************************************
* The inverse MixColumns operation for rounds i such that (i % 4) == 0
****************************************************************************/
void inv_mixcolumns_0(u32* state) {
	u32 tmp;
	for(int i = 0; i < 8; i++) {
		tmp = ROR(state[i],8) & 0x0c0c0c0c;
		state[i] ^= ROR(tmp,2);
		tmp = ROR(state[i],16) & 0xc0c0c0c0;
		state[i] ^= ROR(tmp,4);
		tmp = ROR(state[i],24) & 0x0c0c0c0c;
		state[i] ^= ROR(tmp,30);
	}
}

/****************************************************************************
* The inverse MixColumns operation for rounds i such that (i % 4) == 1
****************************************************************************/
void inv_mixcolumns_1(u32* state) {
	u32 tmp;
	for(int i = 0; i < 8; i++) {
		tmp = ROR(state[i],16) & 0x30303030;
		state[i] ^= ROR(tmp,2);
		tmp = state[i] & 0x03030303;
		state[i] ^= ROR(tmp,28);
		tmp = ROR(state[i],16) & 0x30303030;
		state[i] ^= ROR(tmp,30);
	}
}

/****************************************************************************
* The inverse MixColumns operation for rounds i such that (i % 4) == 2
****************************************************************************/
void inv_mixcolumns_2(u32* state) {
	u32 tmp;
	for(int i = 0; i < 8; i++) {
		tmp = ROR(state[i],24) & 0xc0c0c0c0;
		state[i] ^= ROR(tmp,2);
		tmp = ROR(state[i],16) & 0x0c0c0c0c;
		state[i] ^= ROR(tmp,28);
		tmp = ROR(state[i],8) & 0xc0c0c0c0;
		state[i] ^= ROR(tmp,6);
	}
}

/****************************************************************************
* The inverse MixColumns operation for rounds i such that (i % 4) == 3
****************************************************************************/
void inv_mixcolumns_3(u32* state) {
	u32 tmp;
	for(int i = 0; i < 8; i++) {
		tmp = state[i] & 0x03030303;
		state[i] ^= ROR(tmp,26);
		tmp = state[i] & 0x30303030;
		state[i] ^= ROR(tmp,4);
		tmp = state[i] & 0x03030303;
		state[i] ^= ROR(tmp,30);
	}
}

/****************************************************************************
* Adds the tweakey (including the round constants) to the state.
****************************************************************************/
void add_tweakey(u32* state, const u32* rtk1, const u32* rtk2_3) {
	state[0] ^= rtk1[0] ^ rtk2_3[0];
	state[1] ^= rtk1[1] ^ rtk2_3[1]; 
	state[2] ^= rtk1[2] ^ rtk2_3[2];
	state[3] ^= rtk1[3] ^ rtk2_3[3];
	state[4] ^= rtk1[4] ^ rtk2_3[4];
	state[5] ^= rtk1[5] ^ rtk2_3[5];
	state[6] ^= rtk1[6] ^ rtk2_3[6];
	state[7] ^= rtk1[7] ^ rtk2_3[7];
}

/****************************************************************************
* Encryption of 2 blocks in parallel using SKINNY-128-384.
* The input parameters 'rtk1' and 'rtk2_3' are given seperately to avoid
* unnecessary recomputations of the entire tk schedule during SKINNY-AEAD-M1.
****************************************************************************/
void skinny128_384_encrypt(u8* ctext, u8* ctext_bis, const u8* ptext, 
					const u8* ptext_bis, const tweakey tk) {
	u32 state[8];
	packing(state, ptext, ptext_bis);
	for(int i = 0; i < 14; i++)
		QUADRUPLE_ROUND(state, tk.rtk1 + (i%4)*32, tk.rtk2_3 + i*32);
	unpacking(ctext, ctext_bis, state);
}

/****************************************************************************
* Decryption of 2 blocks in parallel using SKINNY-128-384.
* The input parameters 'rtk1' and 'rtk2_3' are given seperately to avoid
* unnecessary recomputations of the entire tk schedule during SKINNY-AEAD-M1.
****************************************************************************/
void skinny128_384_decrypt(u8* ptext, u8* ptext_bis, const u8* ctext, 
					const u8* ctext_bis, const tweakey tk) {
	u32 state[8];
	packing(state, ctext, ctext_bis);
	for(int i = 13; i >= 0; i--)
		INV_QUADRUPLE_ROUND(state, tk.rtk1 + (i%4)*32, tk.rtk2_3 + i*32);
	unpacking(ptext, ptext_bis, state);
}