/******************************************************************************
* Constant-time implementation of the SKINNY tweakable block ciphers.
*
* This implementation doesn't compute the ShiftRows operation. Some masks and
* shifts are applied during the MixColumns operation so that the proper bits
* are XORed together. Moreover, the row permutation within the MixColumns 
* is omitted, as well as the bit permutation at the end of the Sbox. The rows
* are synchronized with the classical after only 4 rounds. Therefore, this 
* implementation relies on a "QUADRUPLE_ROUND" routine.
*
* The Sbox computation takes advantage of some symmetry in the 8-bit Sbox to
* turn it into a 4-bit S-box computation. Although the last bit permutation
* within the Sbox is not computed, the bit ordering is synchronized with the 
* classical representation after 2 calls.
*
* @author	Alexandre Adomnicai, Nanyang Technological University,
*			alexandre.adomnicai@ntu.edu.sg
*
* @date		May 2020
******************************************************************************/
#include <stdio.h>
#include <string.h>
#include "skinny128.h"
#include "tk_schedule.h"

/******************************************************************************
* The MixColumns computation for rounds i such that (i % 4) == 0
******************************************************************************/
void mixcolumns_0(u32* state) {
	u32 tmp;
	for(int i = 0; i < 4; i++) {
		tmp = ROR(state[i],24) & 0x0c0c0c0c;
		state[i] ^= ROR(tmp,30);
		tmp = ROR(state[i],16) & 0xc0c0c0c0;
		state[i] ^= ROR(tmp,4);
		tmp = ROR(state[i],8) & 0x0c0c0c0c;
		state[i] ^= ROR(tmp,2);
	}
}

/******************************************************************************
* The MixColumns computation for rounds i such that (i % 4) == 1
******************************************************************************/
void mixcolumns_1(u32* state) {
	u32 tmp;
	for(int i = 0; i < 4; i++) {
		tmp = ROR(state[i],16) & 0x30303030;
		state[i] ^= ROR(tmp,30);
		tmp = state[i] & 0x03030303;
		state[i] ^= ROR(tmp,28);
		tmp = ROR(state[i],16) & 0x30303030;
		state[i] ^= ROR(tmp,2);
	}
}

/******************************************************************************
* The MixColumns computation for rounds i such that (i % 4) == 2
******************************************************************************/
void mixcolumns_2(u32* state) {
	u32 tmp;
	for(int i = 0; i < 4; i++) {
		tmp = ROR(state[i],8) & 0xc0c0c0c0;
		state[i] ^= ROR(tmp,6);
		tmp = ROR(state[i],16) & 0x0c0c0c0c;
		state[i] ^= ROR(tmp,28);
		tmp = ROR(state[i],24) & 0xc0c0c0c0;
		state[i] ^= ROR(tmp,2);
	}
}

/******************************************************************************
* The MixColumns computation for rounds i such that (i % 4) == 3
******************************************************************************/
void mixcolumns_3(u32* state) {
	u32 tmp;
	for(int i = 0; i < 4; i++) {
		tmp = state[i] & 0x03030303;
		state[i] ^= ROR(tmp,30);
		tmp = state[i] & 0x30303030;
		state[i] ^= ROR(tmp,4);
		tmp = state[i] & 0x03030303;
		state[i] ^= ROR(tmp,26);
	}
}

/******************************************************************************
* Encryption of a single block without any operation mode using SKINNY-128-384.
* RTK1 and RTK2_3 are given separately to take advantage of the fact that
* TK2 and TK3 remains the same through the entire data encryption/decryption.
******************************************************************************/
void skinny128_384_plus(u8* ctext, const u8* ptext, const u32* rtk1,  
					const u32* rtk2_3) {
	u32 tmp; 					// used in SWAPMOVE macro
	u32 state[4]; 				// 128-bit state
	packing(state, ptext); 		// from byte to bitsliced representation
	QUADRUPLE_ROUND(state, rtk1, 	rtk2_3);
	QUADRUPLE_ROUND(state, rtk1+16, rtk2_3+16);
	QUADRUPLE_ROUND(state, rtk1+32, rtk2_3+32);
	QUADRUPLE_ROUND(state, rtk1+48, rtk2_3+48);
	QUADRUPLE_ROUND(state, rtk1, 	rtk2_3+64);
	QUADRUPLE_ROUND(state, rtk1+16, rtk2_3+80);
	QUADRUPLE_ROUND(state, rtk1+32, rtk2_3+96);
	QUADRUPLE_ROUND(state, rtk1+48, rtk2_3+112);
	QUADRUPLE_ROUND(state, rtk1, 	rtk2_3+128);
	QUADRUPLE_ROUND(state, rtk1+16, rtk2_3+144);
	unpacking(ctext, state);	// from bitsliced to byte representation
}