#include "forkskinny.h"

#include <string.h>
#include <stdint.h>

#include "api.h"

/* 7-bit round constant */
const uint8_t RC[87] = {0x01, 0x03, 0x07, 0x0f, 0x1f, 0x3f, 0x7e, 0x7d, 0x7b, 0x77, 0x6f, 0x5f, 0x3e, 0x7c, 0x79, 0x73, 0x67, 0x4f, 0x1e, 0x3d, 0x7a, 0x75, 0x6b, 0x57, 0x2e, 0x5c, 0x38, 0x70, 0x61, 0x43, 0x06, 0x0d, 0x1b, 0x37, 0x6e, 0x5d, 0x3a, 0x74, 0x69, 0x53, 0x26, 0x4c, 0x18, 0x31, 0x62, 0x45, 0x0a, 0x15, 0x2b, 0x56, 0x2c, 0x58, 0x30, 0x60, 0x41, 0x02, 0x05, 0x0b, 0x17, 0x2f, 0x5e, 0x3c, 0x78, 0x71, 0x63, 0x47, 0x0e, 0x1d, 0x3b, 0x76, 0x6d, 0x5b, 0x36, 0x6c, 0x59, 0x32, 0x64, 0x49, 0x12, 0x25, 0x4a, 0x14, 0x29, 0x52, 0x24, 0x48, 0x10};

#if CRYPTO_BLOCKSIZE == 16
void skinny_round_128(uint8_t state[16], uint8_t *keyCells, int i);
void skinny_round_inv_128(uint8_t state[16], uint8_t *keyCells, int i);
void advanceKeySchedule_128(uint8_t *keyCells);
void reverseKeySchedule_128(uint8_t *keyCells);

void forkEncrypt_128(unsigned char* C0, unsigned char* C1, unsigned char* input, const unsigned char* userkey, const enum encrypt_selector s){

	uint8_t state[16], L[16], keyCells[TWEAKEY_BLOCKSIZE_RATIO*16];
	int i;

	/* Load state and key */
	memcpy(state,input,16);
	memcpy(keyCells,userkey,32);
#if TWEAKEY_BLOCKSIZE_RATIO == 3
	memcpy(&keyCells[32],&userkey[32],16);
#endif

	/* Before fork */
	for(i = 0; i < CRYPTO_NBROUNDS_BEFORE; i++)
		skinny_round_128(state, keyCells, i);

	/* Save fork if both output blocks are needed */
	if (s == ENC_BOTH)
		memcpy(L,state,16);

	/* Right branch (C1) */
	if ((s == ENC_C1) | (s == ENC_BOTH)){
		for(i = CRYPTO_NBROUNDS_BEFORE; i < CRYPTO_NBROUNDS_BEFORE+CRYPTO_NBROUNDS_AFTER; i++)
			skinny_round_128(state, keyCells, i);

		/* Move result to output buffer*/
		memcpy(C1,state,16);
	}

	/* Reinstall L as state if necessary */
	if (s == ENC_BOTH)
		memcpy(state,L,16);

	/* Left branch (C0) */
	if ((s == ENC_C0) | (s == ENC_BOTH)){

		/* Add branch constant */
		state[0] ^= 0x01;  state[1] ^= 0x02;  state[2] ^= 0x04;  state[3] ^= 0x08;
		state[4] ^= 0x10;  state[5] ^= 0x20;  state[6] ^= 0x41;  state[7] ^= 0x82;
		state[8] ^= 0x05;  state[9] ^= 0x0a;  state[10] ^= 0x14;  state[11] ^= 0x28;
		state[12] ^= 0x51;  state[13] ^= 0xa2;  state[14] ^= 0x44;  state[15] ^= 0x88;

		for(i = CRYPTO_NBROUNDS_BEFORE+CRYPTO_NBROUNDS_AFTER; i < CRYPTO_NBROUNDS_BEFORE+2*CRYPTO_NBROUNDS_AFTER; i++)
			skinny_round_128(state, keyCells, i);

		/* Move result to output buffer */
		memcpy(C0,state,16);
	}

	/* Null pointer for invalid outputs */
	if (s == ENC_C0)
		C1 = NULL;
	else if (s == ENC_C1)
		C0 = NULL;
}

void forkInvert_128(unsigned char* inverse, unsigned char* C_other, unsigned char* input, const unsigned char* userkey, uint8_t b, const enum inversion_selector s){

	uint8_t state[16], L[16], keyCells[TWEAKEY_BLOCKSIZE_RATIO*16];
	int i;

	/* Load state and key */
	memcpy(state,input,16);
	memcpy(keyCells,userkey,32);
#if TWEAKEY_BLOCKSIZE_RATIO == 3
	memcpy(&keyCells[32],&userkey[32],16);
#endif

	if (b == 1){

		/* Advance the key schedule in order to decrypt */
		for(i = 0; i < CRYPTO_NBROUNDS_BEFORE+CRYPTO_NBROUNDS_AFTER; i++)
			advanceKeySchedule_128(keyCells);

		/* From C1 to fork*/
		for(i = CRYPTO_NBROUNDS_BEFORE+CRYPTO_NBROUNDS_AFTER-1; i >= CRYPTO_NBROUNDS_BEFORE; i--)
			skinny_round_inv_128(state, keyCells, i);

		/* Save fork if both blocks are needed */
		if (s == INV_BOTH)
			memcpy(L,state,16);

		if ((s == INV_INVERSE) | (s == INV_BOTH)) {
			/* From fork to M */
			for(i = CRYPTO_NBROUNDS_BEFORE-1; i >= 0; i--)
				skinny_round_inv_128(state, keyCells, i);

			/* Move result to output buffer */
			memcpy(inverse,state,16);
		}

		/* Reinstall fork if necessary */
		if (s == INV_BOTH) {
			memcpy(state,L,16);

			for (i=0; i<CRYPTO_NBROUNDS_BEFORE; i++)
				advanceKeySchedule_128(keyCells);
		}

		if ((s == INV_OTHER) | (s == INV_BOTH)) {
			/* Set correct keyschedule */
			for (i=0; i<CRYPTO_NBROUNDS_AFTER; i++)
				advanceKeySchedule_128(keyCells);

			/* Add branch constant */
			state[0] ^= 0x01;  state[1] ^= 0x02;  state[2] ^= 0x04;  state[3] ^= 0x08;
			state[4] ^= 0x10;  state[5] ^= 0x20;  state[6] ^= 0x41;  state[7] ^= 0x82;
			state[8] ^= 0x05;  state[9] ^= 0x0a;  state[10] ^= 0x14;  state[11] ^= 0x28;
			state[12] ^= 0x51;  state[13] ^= 0xa2;  state[14] ^= 0x44;  state[15] ^= 0x88;

			/* From fork to C0 */
			for(i = CRYPTO_NBROUNDS_BEFORE+CRYPTO_NBROUNDS_AFTER; i < CRYPTO_NBROUNDS_BEFORE+2*CRYPTO_NBROUNDS_AFTER; i++)
				skinny_round_128(state, keyCells, i);

			/* Move result to output buffer */
			memcpy(C_other,state,16);
		}
	}
	else {
		/* Advance the key schedule in order to decrypt */
		for(i = 0; i < CRYPTO_NBROUNDS_BEFORE+2*CRYPTO_NBROUNDS_AFTER; i++)
			advanceKeySchedule_128(keyCells);

		/* From C0 to fork */
		for(i = CRYPTO_NBROUNDS_BEFORE+2*CRYPTO_NBROUNDS_AFTER-1; i >= CRYPTO_NBROUNDS_BEFORE+CRYPTO_NBROUNDS_AFTER; i--)
			skinny_round_inv_128(state, keyCells, i);

		/* Add branch constant */
		state[0] ^= 0x01;  state[1] ^= 0x02;  state[2] ^= 0x04;  state[3] ^= 0x08;
		state[4] ^= 0x10;  state[5] ^= 0x20;  state[6] ^= 0x41;  state[7] ^= 0x82;
		state[8] ^= 0x05;  state[9] ^= 0x0a;  state[10] ^= 0x14;  state[11] ^= 0x28;
		state[12] ^= 0x51;  state[13] ^= 0xa2;  state[14] ^= 0x44;  state[15] ^= 0x88;

		/* Save fork if both blocks are needed */
		if (s == INV_BOTH)
			memcpy(L,state,16);

		/* Set correct keyschedule */
		for(i = 0; i < CRYPTO_NBROUNDS_AFTER; i++)
			reverseKeySchedule_128(keyCells);

		if ((s == INV_BOTH) | (s == INV_INVERSE)) {
			/* From fork to M */
			for(i = CRYPTO_NBROUNDS_BEFORE-1; i >= 0; i--)
				skinny_round_inv_128(state, keyCells, i);

			/* Move result into output buffer */
			memcpy(inverse,state,16);
		}

		/* Reinstall fork and correct key schedule if necessary */
		if (s == INV_BOTH) {
			memcpy(state,L,16);

			for (i=0; i<CRYPTO_NBROUNDS_BEFORE; i++)
				advanceKeySchedule_128(keyCells);
		}

		if ((s == INV_BOTH) | (s == INV_OTHER)) {
			/* From fork to C1 */
			for(i = CRYPTO_NBROUNDS_BEFORE; i < CRYPTO_NBROUNDS_BEFORE+CRYPTO_NBROUNDS_AFTER; i++) // for i in range(nbRounds)
				skinny_round_128(state, keyCells, i);

			/* Move result to output buffer */
			memcpy(C_other,state,16);
		}
	}

	/* Null pointer for invalid outputs */
	if (s == INV_INVERSE)
		C_other = NULL;
	else if (s == INV_OTHER)
		inverse = NULL;
}


uint8_t skinny128_sbox(uint8_t x);
uint8_t skinny128_inv_sbox(uint8_t x);

void skinny_round_128(uint8_t state[16], uint8_t *keyCells, int i){
	uint8_t temp;

	/* SubCell */
	state[0] = skinny128_sbox(state[0]);   state[1] = skinny128_sbox(state[1]);   state[2] = skinny128_sbox(state[2]);   state[3] = skinny128_sbox(state[3]);
	state[4] = skinny128_sbox(state[4]);   state[5] = skinny128_sbox(state[5]);   state[6] = skinny128_sbox(state[6]);   state[7] = skinny128_sbox(state[7]);
	state[8] = skinny128_sbox(state[8]);   state[9] = skinny128_sbox(state[9]);   state[10] = skinny128_sbox(state[10]); state[11] = skinny128_sbox(state[11]);
	state[12] = skinny128_sbox(state[12]); state[13] = skinny128_sbox(state[13]); state[14] = skinny128_sbox(state[14]); state[15] = skinny128_sbox(state[15]);

	/* AddConstants */
	state[0] ^= (RC[i] & 0xf);
	state[4] ^= ((RC[i]>>4) & 0x7);
	state[8] ^= 0x2;
	/* Indicate tweak material */
	state[2] ^= 0x2;

	/* AddKey  */
	//TK1
	state[0] ^= keyCells[0];	state[1] ^= keyCells[1];	state[2] ^= keyCells[2];	state[3] ^= keyCells[3];	state[4] ^= keyCells[4];	state[5] ^= keyCells[5];	state[6] ^= keyCells[6];	state[7] ^= keyCells[7];
	//TK2
	state[0] ^= keyCells[16];	state[1] ^= keyCells[17];	state[2] ^= keyCells[18];	state[3] ^= keyCells[19];	state[4] ^= keyCells[20];	state[5] ^= keyCells[21];	state[6] ^= keyCells[22];	state[7] ^= keyCells[23];
	//TK3
#if TWEAKEY_BLOCKSIZE_RATIO == 3
	state[0] ^= keyCells[32];	state[1] ^= keyCells[33];	state[2] ^= keyCells[34];	state[3] ^= keyCells[35];	state[4] ^= keyCells[36];	state[5] ^= keyCells[37];	state[6] ^= keyCells[38];	state[7] ^= keyCells[39];
#endif

	/* Advance TKS */
	advanceKeySchedule_128(keyCells);

	/* ShiftRows */
	temp = state[7]; state[7] = state[6]; state[6] = state[5]; state[5] = state[4]; state[4] = temp;
	temp = state[11]; state[11] = state[9]; state[9] = temp; temp = state[10]; state[10] = state[8]; state[8] = temp;	
	temp = state[12]; state[12] = state[13]; state[13] = state[14]; state[14] = state[15]; state[15] = temp;	

	/* MixColumns */
	state[4]^=state[8]; state[8]^=state[0]; state[12]^=state[8]; temp=state[12]; state[12]=state[8]; state[8]=state[4]; state[4]=state[0]; state[0]=temp;
	state[5]^=state[9]; state[9]^=state[1]; state[13]^=state[9]; temp=state[13]; state[13]=state[9]; state[9]=state[5]; state[5]=state[1]; state[1]=temp;
	state[6]^=state[10]; state[10]^=state[2]; state[14]^=state[10]; temp=state[14]; state[14]=state[10]; state[10]=state[6]; state[6]=state[2]; state[2]=temp;
	state[7]^=state[11]; state[11]^=state[3]; state[15]^=state[11]; temp=state[15]; state[15]=state[11]; state[11]=state[7]; state[7]=state[3]; state[3]=temp;

}

void skinny_round_inv_128(uint8_t state[16], uint8_t *keyCells, int i){
	uint8_t temp;

	/* MixColumn_inv */
	temp=state[12]; state[12]=state[0];	state[0]=state[4];	state[4]=state[8];	state[8]=temp;	state[12]^=state[8];	state[8]^=state[0];	state[4]^=state[8];
	temp=state[13];	state[13]=state[1];	state[1]=state[5];	state[5]=state[9];	state[9]=temp;	state[13]^=state[9];	state[9]^=state[1];	state[5]^=state[9];
	temp=state[14];	state[14]=state[2];	state[2]=state[6];	state[6]=state[10];	state[10]=temp;	state[14]^=state[10];	state[10]^=state[2];	state[6]^=state[10];
	temp=state[15];	state[15]=state[3];	state[3]=state[7];	state[7]=state[11];	state[11]=temp;	state[15]^=state[11];	state[11]^=state[3];	state[7]^=state[11];

	/* ShiftRows_inv */
	temp = state[4]; state[4] = state[5]; state[5] = state[6]; state[6] = state[7]; state[7] = temp;
	temp = state[11]; state[11] = state[9]; state[9] = temp; temp = state[10]; state[10] = state[8]; state[8] = temp;	
	temp = state[15]; state[15] = state[14]; state[14] = state[13]; state[13] = state[12]; state[12] = temp;	


	/* Reverse TKS */
	reverseKeySchedule_128(keyCells);

	/* AddKey_inv */
	//TK1
	state[0] ^= keyCells[0];	state[1] ^= keyCells[1];	state[2] ^= keyCells[2];	state[3] ^= keyCells[3];	state[4] ^= keyCells[4];	state[5] ^= keyCells[5];	state[6] ^= keyCells[6];	state[7] ^= keyCells[7];
	//TK2
	state[0] ^= keyCells[16];	state[1] ^= keyCells[17];	state[2] ^= keyCells[18];	state[3] ^= keyCells[19];	state[4] ^= keyCells[20];	state[5] ^= keyCells[21];	state[6] ^= keyCells[22];	state[7] ^= keyCells[23];
	//TK3
#if TWEAKEY_BLOCKSIZE_RATIO == 3
	state[0] ^= keyCells[32];	state[1] ^= keyCells[33];	state[2] ^= keyCells[34];	state[3] ^= keyCells[35];	state[4] ^= keyCells[36];	state[5] ^= keyCells[37];	state[6] ^= keyCells[38];	state[7] ^= keyCells[39];
#endif

	/* AddConstants */
	state[0] ^= (RC[i] & 0xf);
	state[4] ^= ((RC[i]>>4) & 0x7);
	state[8] ^= 0x2;
	/* Indicate tweak material */
	state[2] ^= 0x2;

	/* SubCell_inv */
	state[0] = skinny128_inv_sbox(state[0]);   state[1] = skinny128_inv_sbox(state[1]);   state[2] = skinny128_inv_sbox(state[2]);   state[3] = skinny128_inv_sbox(state[3]);
	state[4] = skinny128_inv_sbox(state[4]);   state[5] = skinny128_inv_sbox(state[5]);   state[6] = skinny128_inv_sbox(state[6]);   state[7] = skinny128_inv_sbox(state[7]);
	state[8] = skinny128_inv_sbox(state[8]);   state[9] = skinny128_inv_sbox(state[9]);   state[10] = skinny128_inv_sbox(state[10]); state[11] = skinny128_inv_sbox(state[11]);
	state[12] = skinny128_inv_sbox(state[12]); state[13] = skinny128_inv_sbox(state[13]); state[14] = skinny128_inv_sbox(state[14]); state[15] = skinny128_inv_sbox(state[15]);
}

uint8_t skinny128_sbox(uint8_t x)
{
	/* Original version from the specification is equivalent to:
	 *
	 * #define SBOX_MIX(x)
	 *     (((~((((x) >> 1) | (x)) >> 2)) & 0x11) ^ (x))
	 * #define SBOX_SWAP(x)
	 *     (((x) & 0xF9) |
	 *     (((x) >> 1) & 0x02) |
	 *     (((x) << 1) & 0x04))
	 * #define SBOX_PERMUTE(x)
	 *     ((((x) & 0x01) << 2) |
	 *      (((x) & 0x06) << 5) |
	 *      (((x) & 0x20) >> 5) |
	 *      (((x) & 0xC8) >> 2) |
	 *      (((x) & 0x10) >> 1))
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
	 * final permutation.  This reduces the number of shift operations.
	 *
	 * We can further reduce the number of NOT operations from 7 to 2
	 * using the technique from https://github.com/kste/skinny_avx to
	 * convert NOR-XOR operations into AND-XOR operations by converting
	 * the S-box into its NOT-inverse.
	 */
	uint8_t y;

	/* Mix the bits */
	x = ~x;
	x ^= (((x >> 2) & (x >> 3)) & 0x11);
	y  = (((x << 5) & (x << 1)) & 0x20);
	x ^= (((x << 5) & (x << 4)) & 0x40) ^ y;
	y  = (((x << 2) & (x << 1)) & 0x80);
	x ^= (((x >> 2) & (x << 1)) & 0x02) ^ y;
	y  = (((x >> 5) & (x << 1)) & 0x04);
	x ^= (((x >> 1) & (x >> 2)) & 0x08) ^ y;
	x = ~x;

	/* Permutation generated by http://programming.sirrida.de/calcperm.php
       The final permutation for each byte is [2 7 6 1 3 0 4 5] */
	return 	((x & 0x08) << 1) |
			((x & 0x32) << 2) |
			((x & 0x01) << 5) |
			((x & 0x80) >> 6) |
			((x & 0x40) >> 4) |
			((x & 0x04) >> 2);
}

uint8_t skinny128_inv_sbox(uint8_t x)
{
	/* Original version from the specification is equivalent to:
	 *
	 * #define SBOX_MIX(x)
	 *     (((~((((x) >> 1) | (x)) >> 2)) & 0x11) ^ (x))
	 * #define SBOX_SWAP(x)
	 *     (((x) & 0xF9) |
	 *     (((x) >> 1) & 0x02) |
	 *     (((x) << 1) & 0x04))
	 * #define SBOX_PERMUTE_INV(x)
	 *     ((((x) & 0x08) << 1) |
	 *      (((x) & 0x32) << 2) |
	 *      (((x) & 0x01) << 5) |
	 *      (((x) & 0xC0) >> 5) |
	 *      (((x) & 0x04) >> 2))
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
	 * final permutation.  This reduces the number of shift operations.
	 */
	uint8_t y;

	/* Mix the bits */
	x = ~x;
	y  = (((x >> 1) & (x >> 3)) & 0x01);
	x ^= (((x >> 2) & (x >> 3)) & 0x10) ^ y;
	y  = (((x >> 6) & (x >> 1)) & 0x02);
	x ^= (((x >> 1) & (x >> 2)) & 0x08) ^ y;
	y  = (((x << 2) & (x << 1)) & 0x80);
	x ^= (((x >> 1) & (x << 2)) & 0x04) ^ y;
	y  = (((x << 5) & (x << 1)) & 0x20);
	x ^= (((x << 4) & (x << 5)) & 0x40) ^ y;
	x = ~x;

	/* Permutation generated by http://programming.sirrida.de/calcperm.php
       The final permutation for each byte is [5 3 0 4 6 7 2 1] */
	return  ((x & 0x01) << 2) |
			((x & 0x04) << 4) |
			((x & 0x02) << 6) |
			((x & 0x20) >> 5) |
			((x & 0xC8) >> 2) |
			((x & 0x10) >> 1);
}


#define skinny128_LFSR2(x) \
    do { \
        uint8_t _x = (x); \
        (x) = ((_x << 1) & 0xFE) ^ \
             (((_x >> 7) ^ (_x >> 5)) & 0x01); \
    } while (0)


#define skinny128_LFSR3(x) \
    do { \
        uint8_t _x = (x); \
        (x) = ((_x >> 1) & 0x7F) ^ \
              (((_x << 7) ^ (_x << 1)) & 0x80); \
    } while (0)

/* LFSR2 and LFSR3 are inverses of each other */
#define skinny128_inv_LFSR2(x) skinny128_LFSR3(x)
#define skinny128_inv_LFSR3(x) skinny128_LFSR2(x)

#define skinny128_permute_tk(tk) \
    do { \
	uint8_t tmp[8]; \
        /* PT = [9, 15, 8, 13, 10, 14, 12, 11, 0, 1, 2, 3, 4, 5, 6, 7] */ \
	memcpy(tmp, &tk[8], 8); \
	memcpy(&tk[8], tk, 8); \
	tk[0] = tmp[1]; tk[1] = tmp[7]; tk[2] = tmp[0]; tk[3] = tmp[5]; \
	tk[4] = tmp[2]; tk[5] = tmp[6]; tk[6] = tmp[4]; tk[7] = tmp[3]; \
    } while (0)

#define skinny128_inv_permute_tk(tk) \
    do { \
    uint8_t tmp[8]; \
        /* PT = [9, 15, 8, 13, 10, 14, 12, 11, 0, 1, 2, 3, 4, 5, 6, 7] */ \
	memcpy(tmp, tk, 8); \
	memcpy(tk, &tk[8], 8); \
	tk[9] = tmp[0]; tk[15] = tmp[1]; tk[8] = tmp[2]; tk[13] = tmp[3]; \
	tk[10] = tmp[4]; tk[14] = tmp[5]; tk[12] = tmp[6]; tk[11] = tmp[7]; \
    } while (0)

/* ADVANCE THE KEY SCHEDULE ONCE */
void advanceKeySchedule_128(uint8_t *keyCells)
{
	// update the subtweakey states with the permutation
	skinny128_permute_tk(keyCells);
	skinny128_permute_tk((&keyCells[16]));
#if TWEAKEY_BLOCKSIZE_RATIO ==3
	skinny128_permute_tk((&keyCells[32]));
#endif

	//update the subtweakey states with the LFSRs
	//TK2
	skinny128_LFSR2(keyCells[16]); skinny128_LFSR2(keyCells[17]); skinny128_LFSR2(keyCells[18]); skinny128_LFSR2(keyCells[19]);
	skinny128_LFSR2(keyCells[20]); skinny128_LFSR2(keyCells[21]); skinny128_LFSR2(keyCells[22]); skinny128_LFSR2(keyCells[23]);
	//TK3
#if TWEAKEY_BLOCKSIZE_RATIO ==3
	skinny128_LFSR3(keyCells[32]); skinny128_LFSR3(keyCells[33]); skinny128_LFSR3(keyCells[34]); skinny128_LFSR3(keyCells[35]);
	skinny128_LFSR3(keyCells[36]); skinny128_LFSR3(keyCells[37]); skinny128_LFSR3(keyCells[38]); skinny128_LFSR3(keyCells[39]);
#endif
}

/* REVERSE THE KEY SCHEDULE ONCE (used in decryption and reconstruction) */
void reverseKeySchedule_128(uint8_t *keyCells){
	//update the subtweakey states with the LFSRs
	//TK2
	skinny128_inv_LFSR2(keyCells[16]); skinny128_inv_LFSR2(keyCells[17]); skinny128_inv_LFSR2(keyCells[18]); skinny128_inv_LFSR2(keyCells[19]);
	skinny128_inv_LFSR2(keyCells[20]); skinny128_inv_LFSR2(keyCells[21]); skinny128_inv_LFSR2(keyCells[22]); skinny128_inv_LFSR2(keyCells[23]);
	//TK3
#if TWEAKEY_BLOCKSIZE_RATIO ==3
	skinny128_inv_LFSR3(keyCells[32]); skinny128_inv_LFSR3(keyCells[33]); skinny128_inv_LFSR3(keyCells[34]); skinny128_inv_LFSR3(keyCells[35]);
	skinny128_inv_LFSR3(keyCells[36]); skinny128_inv_LFSR3(keyCells[37]); skinny128_inv_LFSR3(keyCells[38]); skinny128_inv_LFSR3(keyCells[39]);
#endif

	// update the subtweakey states with the permutation
	skinny128_inv_permute_tk(keyCells);
	skinny128_inv_permute_tk((&keyCells[16]));
#if TWEAKEY_BLOCKSIZE_RATIO ==3
	skinny128_inv_permute_tk((&keyCells[32]));
#endif
}

#else

void skinny_round_64(uint8_t state[8], uint8_t *keyCells, int i);
void skinny_round_inv_64(uint8_t state[4], uint8_t *keyCells, int i);
void advanceKeySchedule_64(uint8_t *keyCells);
void reverseKeySchedule_64(uint8_t *keyCells);

void forkEncrypt_64(unsigned char* C0, unsigned char* C1, unsigned char* input, const unsigned char* userkey, const enum encrypt_selector s){

	uint8_t state[8], L[8], keyCells[TWEAKEY_BLOCKSIZE_RATIO*8];
	int i;

	/* Load state and key */
	memcpy(state, input, 8);
	memcpy(keyCells, userkey, 16);
#if TWEAKEY_BLOCKSIZE_RATIO == 3
	memcpy(&keyCells[16], &userkey[16], 8);
#endif

	/* Before fork */
	for(i = 0; i < CRYPTO_NBROUNDS_BEFORE; i++)
		skinny_round_64(state, keyCells, i);

	/* Save fork if both output blocks are needed */
	if (s == ENC_BOTH)
		memcpy(L,state,8);

	/* Right branch (C1) */
	if ((s == ENC_C1) | (s == ENC_BOTH)){
		for(i = CRYPTO_NBROUNDS_BEFORE; i < CRYPTO_NBROUNDS_BEFORE+CRYPTO_NBROUNDS_AFTER; i++)
			skinny_round_64(state, keyCells, i);

		/* Move result to output buffer*/
		memcpy(C1, state, 8);
	}

	/* Reinstall L as state if necessary */
	if (s == ENC_BOTH)
		memcpy(state,L,8);

	/* Left branch (C0) */
	if ((s == ENC_C0) | (s == ENC_BOTH)){

		/* Add branch constant */
		state[0] ^= 0x12;  state[1] ^= 0x49;  state[2] ^= 0x36;  state[3] ^= 0xda;
		state[4] ^= 0x5b;  state[5] ^= 0x7f;  state[6] ^= 0xec;  state[7] ^= 0x81;

		for(i = CRYPTO_NBROUNDS_BEFORE+CRYPTO_NBROUNDS_AFTER; i < CRYPTO_NBROUNDS_BEFORE+2*CRYPTO_NBROUNDS_AFTER; i++)
			skinny_round_64(state, keyCells, i);

		/* Move result to output buffer */
		memcpy(C0, state, 8);
	}

	/* Null pointer for invalid outputs */
	if (s == ENC_C0)
		C1 = NULL;
	else if (s == ENC_C1)
		C0 = NULL;

}

void forkInvert_64(unsigned char* inverse, unsigned char* C_other, unsigned char* input, const unsigned char* userkey, uint8_t b, const enum inversion_selector s){

	uint8_t state[8], L[8], keyCells[TWEAKEY_BLOCKSIZE_RATIO*8];
	int i;

	/* Load state and key */
	memcpy(state, input, 8);
	memcpy(keyCells, userkey, 16);
#if TWEAKEY_BLOCKSIZE_RATIO == 3
	memcpy(&keyCells[16], &userkey[16], 8);
#endif

	if (b == 1){

		/* Advance the key schedule in order to decrypt */
		for(i = 0; i < CRYPTO_NBROUNDS_BEFORE+CRYPTO_NBROUNDS_AFTER; i++)
			advanceKeySchedule_64(keyCells);

		/* From C1 to fork*/
		for(i = CRYPTO_NBROUNDS_BEFORE+CRYPTO_NBROUNDS_AFTER-1; i >= CRYPTO_NBROUNDS_BEFORE; i--)
			skinny_round_inv_64(state, keyCells, i);

		/* Save fork if both blocks are needed */
		if (s == INV_BOTH)
			memcpy(L,state,8);

		if ((s == INV_INVERSE) | (s == INV_BOTH)) {
			/* From fork to M */
			for(i = CRYPTO_NBROUNDS_BEFORE-1; i >= 0; i--)
				skinny_round_inv_64(state, keyCells, i);

			/* Move result to output buffer */
			memcpy(inverse, state, 8);
		}

		/* Reinstall fork if necessary */
		if (s == INV_BOTH) {
			memcpy(state,L,8);

			for (i=0; i<CRYPTO_NBROUNDS_BEFORE; i++)
				advanceKeySchedule_64(keyCells);
		}

		if ((s == INV_OTHER) | (s == INV_BOTH)) {
			/* Set correct keyschedule */
			for (i=0; i<CRYPTO_NBROUNDS_AFTER; i++)
				advanceKeySchedule_64(keyCells);

			/* Add branch constant */
			state[0] ^= 0x12;  state[1] ^= 0x49;  state[2] ^= 0x36;  state[3] ^= 0xda;
			state[4] ^= 0x5b;  state[5] ^= 0x7f;  state[6] ^= 0xec;  state[7] ^= 0x81;
			/* From fork to C0 */
			for(i = CRYPTO_NBROUNDS_BEFORE+CRYPTO_NBROUNDS_AFTER; i < CRYPTO_NBROUNDS_BEFORE+2*CRYPTO_NBROUNDS_AFTER; i++)
				skinny_round_64(state, keyCells, i);

			/* Move result to output buffer */
			memcpy(C_other, state, 8);
		}
	}
	else {
		/* Advance the key schedule in order to decrypt */
		for(i = 0; i < CRYPTO_NBROUNDS_BEFORE+2*CRYPTO_NBROUNDS_AFTER; i++)
			advanceKeySchedule_64(keyCells);

		/* From C0 to fork */
		for(i = CRYPTO_NBROUNDS_BEFORE+2*CRYPTO_NBROUNDS_AFTER-1; i >= CRYPTO_NBROUNDS_BEFORE+CRYPTO_NBROUNDS_AFTER; i--)
			skinny_round_inv_64(state, keyCells, i);

		/* Add branch constant */
		state[0] ^= 0x12;  state[1] ^= 0x49;  state[2] ^= 0x36;  state[3] ^= 0xda;
		state[4] ^= 0x5b;  state[5] ^= 0x7f;  state[6] ^= 0xec;  state[7] ^= 0x81;

		/* Save fork if both blocks are needed */
		if (s == INV_BOTH)
			memcpy(L,state,8);

		/* Set correct keyschedule */
		for(i = 0; i < CRYPTO_NBROUNDS_AFTER; i++)
			reverseKeySchedule_64(keyCells);

		if ((s == INV_BOTH) | (s == INV_INVERSE)) {
			/* From fork to M */
			for(i = CRYPTO_NBROUNDS_BEFORE-1; i >= 0; i--)
				skinny_round_inv_64(state, keyCells, i);

			/* Move result into output buffer */
			memcpy(inverse, state, 8);
		}

		/* Reinstall fork and correct key schedule if necessary */
		if (s == INV_BOTH) {
			memcpy(state,L,8);

			for (i=0; i<CRYPTO_NBROUNDS_BEFORE; i++)
				advanceKeySchedule_64(keyCells);
		}

		if ((s == INV_BOTH) | (s == INV_OTHER)) {
			/* From fork to C1 */
			for(i = CRYPTO_NBROUNDS_BEFORE; i < CRYPTO_NBROUNDS_BEFORE+CRYPTO_NBROUNDS_AFTER; i++) // for i in range(nbRounds)
				skinny_round_64(state, keyCells, i);

			/* Move result to output buffer */
			memcpy(C_other, state, 8);		
			}
	}

	/* Null pointer for invalid outputs */
	if (s == INV_INVERSE)
		C_other = NULL;
	else if (s == INV_OTHER)
		inverse = NULL;
}


//uint8_t skinny64_sbox(uint8_t x);
#define skinny64_sbox(x) \
do { \
	x = ~x; \
	x = (((x >> 3) & (x >> 2)) & 0x11) ^ x; \
	x = (((x << 1) & (x << 2)) & 0x88) ^ x; \
	x = (((x << 1) & (x << 2)) & 0x44) ^ x; \
	x = (((x >> 2) & (x << 1)) & 0x22) ^ x; \
	x = ~x; \
	x = ((x >> 1) & 0x77) | ((x << 3) & 0x88);\
	} while (0)

uint8_t skinny64_inv_sbox(uint8_t x);

void skinny_round_64(uint8_t state[8], uint8_t *keyCells, int i){
	uint8_t temp;

	/* SubCell */
	//state[0] = skinny64_sbox(state[0]); state[1] = skinny64_sbox(state[1]); state[2] = skinny64_sbox(state[2]); state[3] = skinny64_sbox(state[3]);
	//state[4] = skinny64_sbox(state[4]); state[5] = skinny64_sbox(state[5]); state[6] = skinny64_sbox(state[6]); state[7] = skinny64_sbox(state[7]);
	skinny64_sbox(state[0]); skinny64_sbox(state[1]); skinny64_sbox(state[2]); skinny64_sbox(state[3]);
	skinny64_sbox(state[4]); skinny64_sbox(state[5]); skinny64_sbox(state[6]); skinny64_sbox(state[7]);


	/* AddConstants */
	state[0] ^=  ((RC[i] & 0xf) <<4);
	state[1] ^= 0x20;	//Indicate tweak material
	state[2] ^= (RC[i] & 0x70);
	state[4] ^= 0x20;

	/* AddKey  */
	//TK1
	state[0] ^= keyCells[0]; state[1] ^= keyCells[1]; state[2] ^= keyCells[2]; state[3] ^= keyCells[3];
	//TK2
	state[0] ^= keyCells[8]; state[1] ^= keyCells[9]; state[2] ^= keyCells[10]; state[3] ^= keyCells[11];		
#if TWEAKEY_BLOCKSIZE_RATIO == 3
	//TK3
	state[0] ^= keyCells[16]; state[1] ^= keyCells[17]; state[2] ^= keyCells[18]; state[3] ^= keyCells[19];		
#endif

	/* Advance TKS */
	advanceKeySchedule_64(keyCells);

	/* ShiftRows */
	temp = (state[3]<<4) | (state[2]>>4); state[3] = (state[2]<<4) | (state[3]>>4); state[2] = temp;
	temp = state[4]; state[4] = state[5]; state[5] = temp;
	temp = (state[7]>>4 | state[6] <<4); state[7] = (state[6]>>4 | state[7] <<4); state[6] = temp;

	/* MixColumns */
	state[2]^=state[4]; state[4]^=state[0]; state[6]^=state[4]; temp=state[6]; state[6]=state[4]; state[4]=state[2]; state[2]=state[0]; state[0]=temp;
	state[3]^=state[5]; state[5]^=state[1]; state[7]^=state[5]; temp=state[7]; state[7]=state[5]; state[5]=state[3]; state[3]=state[1]; state[1]=temp;
}

void skinny_round_inv_64(uint8_t state[8], uint8_t *keyCells, int i){
	uint16_t temp;

	/* MixColumn_inv */
	temp=state[6]; state[6]=state[0]; state[0]=state[2]; state[2]=state[4];	state[4]=temp;	state[6]^=state[4]; state[4]^=state[0];	state[2]^=state[4];
	temp=state[7];	state[7]=state[1]; state[1]=state[3]; state[3]=state[5]; state[5]=temp; state[7]^=state[5]; state[5]^=state[1]; state[3]^=state[5];

	/* ShiftRows_inv */
	temp = (state[2]<<4) | (state[3]>>4); state[3] = (state[3]<<4) | (state[2]>>4); state[2] = temp;
	temp = state[4]; state[4] = state[5]; state[5] = temp;
	temp = (state[6]>>4 | state[7] <<4); state[7] = (state[7]>>4 | state[6] <<4); state[6] = temp;

	/* Reverse TKS */
	reverseKeySchedule_64(keyCells);

	/* AddKey_inv */
	//TK1
	state[0] ^= keyCells[0]; state[1] ^= keyCells[1]; state[2] ^= keyCells[2]; state[3] ^= keyCells[3];
	//TK2
	state[0] ^= keyCells[8]; state[1] ^= keyCells[9]; state[2] ^= keyCells[10]; state[3] ^= keyCells[11];		
#if TWEAKEY_BLOCKSIZE_RATIO == 3
	//TK3
	state[0] ^= keyCells[16]; state[1] ^= keyCells[17]; state[2] ^= keyCells[18]; state[3] ^= keyCells[19];		
#endif

	/* AddConstants */
	state[0] ^=  ((RC[i] & 0xf) <<4);
	state[1] ^= 0x20;	//Indicate tweak material
	state[2] ^= (RC[i] & 0x70);
	state[4] ^= 0x20;

	/* SubCell_inv */
	state[0] = skinny64_inv_sbox(state[0]); state[1] = skinny64_inv_sbox(state[1]); state[2] = skinny64_inv_sbox(state[2]); state[3] = skinny64_inv_sbox(state[3]);
	state[4] = skinny64_inv_sbox(state[4]); state[5] = skinny64_inv_sbox(state[5]); state[6] = skinny64_inv_sbox(state[6]); state[7] = skinny64_inv_sbox(state[7]);
}


/*uint8_t skinny64_sbox(uint8_t x){
	x = ~x;
	x = (((x >> 3) & (x >> 2)) & 0x11) ^ x;
	x = (((x << 1) & (x << 2)) & 0x88) ^ x;
	x = (((x << 1) & (x << 2)) & 0x44) ^ x;
	x = (((x >> 2) & (x << 1)) & 0x22) ^ x;
	x = ~x;
	return ((x >> 1) & 0x77) | ((x << 3) & 0x88);
}*/

uint8_t skinny64_inv_sbox(uint8_t x){
	x = ~x;
	x = (((x >> 3) & (x >> 2)) & 0x11) ^ x;
	x = (((x << 1) & (x >> 2)) & 0x22) ^ x;
	x = (((x << 1) & (x << 2)) & 0x44) ^ x;
	x = (((x << 1) & (x << 2)) & 0x88) ^ x;
	x = ~x;
	return ((x << 1) & 0xEE) | ((x >> 3) & 0x11);
}

#define permute_tk_64(tk) \
	do { \
	/* PT = [9, 15, 8, 13, 10, 14, 12, 11, 0, 1, 2, 3, 4, 5, 6, 7] */ \
	uint8_t tmp[4]; \
	memcpy(tmp, &tk[4], 4); \
	memcpy(&tk[4], tk, 4); \
	tk[0] = (tmp[3] & 0x0F) | (tmp[0] << 4); \
	tk[1] = (tmp[2] & 0x0F) | (tmp[0] & 0xF0); \
	tk[2] = (tmp[3] >> 4) | (tmp[1] & 0xF0); \
	tk[3] = (tmp[1] & 0x0F) | (tmp[2] & 0xF0); \
	} while(0)


#define inv_permute_tk_64(tk) \
	do { \
	/* PT' = [8, 9, 10, 11, 12, 13, 14, 15, 2, 0, 4, 7, 6, 3, 5, 1] */ \
	uint8_t tmp[4]; \
	memcpy(tmp, tk, 4); \
	memcpy(tk, &tk[4], 4); \
	tk[4] = (tmp[0] >> 4) | (tmp[1] & 0xF0); \
	tk[5] = (tmp[3] & 0x0F) | (tmp[2] & 0xF0); \
	tk[6] = (tmp[1] & 0x0F) | (tmp[3] & 0xF0); \
	tk[7] = (tmp[0] & 0x0F) | (tmp[2] << 4); \
	} while(0)

#define skinny64_LFSR2(x) \
    do { \
        uint8_t _x = (x); \
        (x) = ((_x << 1) & 0xEE) ^ (((_x >> 3) ^ (_x >> 2)) & 0x11); \
    } while (0)

#define skinny64_LFSR3(x) \
    do { \
        uint8_t _x = (x); \
        (x) = ((_x >> 1) & 0x77) ^ ((_x ^ (_x << 3)) & 0x88); \
    } while (0)

/* LFSR2 and LFSR3 are inverses of each other */
#define skinny64_inv_LFSR2(x) skinny64_LFSR3(x)
#define skinny64_inv_LFSR3(x) skinny64_LFSR2(x)

/* ADVANCE THE KEY SCHEDULE ONCE */
void advanceKeySchedule_64(uint8_t *keyCells){
	// update the subtweakey states with the permutation
	permute_tk_64(keyCells);
	permute_tk_64((&keyCells[8]));
#if TWEAKEY_BLOCKSIZE_RATIO ==3
	permute_tk_64((&keyCells[16]));
#endif

	//update the subtweakey states with the LFSRs
	//TK2
	skinny64_LFSR2(keyCells[8]); skinny64_LFSR2(keyCells[9]);
	skinny64_LFSR2(keyCells[10]); skinny64_LFSR2(keyCells[11]);
	//TK3
#if TWEAKEY_BLOCKSIZE_RATIO ==3
	skinny64_LFSR3(keyCells[16]); skinny64_LFSR3(keyCells[17]);
	skinny64_LFSR3(keyCells[18]); skinny64_LFSR3(keyCells[19]);
#endif
}

/* REVERSE THE KEY SCHEDULE ONCE (used in decryption and reconstruction) */
void reverseKeySchedule_64(uint8_t *keyCells){
	//update the subtweakey states with the LFSRs
	//TK2
	skinny64_inv_LFSR2(keyCells[8]); skinny64_inv_LFSR2(keyCells[9]);
	skinny64_inv_LFSR2(keyCells[10]); skinny64_inv_LFSR2(keyCells[11]);
	//TK3
#if TWEAKEY_BLOCKSIZE_RATIO ==3
	skinny64_inv_LFSR3(keyCells[16]); skinny64_inv_LFSR3(keyCells[17]);
	skinny64_inv_LFSR3(keyCells[18]); skinny64_inv_LFSR3(keyCells[19]);
#endif

	// update the subtweakey states with the permutation
	inv_permute_tk_64(keyCells);
	inv_permute_tk_64((&keyCells[8]));
#if TWEAKEY_BLOCKSIZE_RATIO ==3
	inv_permute_tk_64((&keyCells[16]));
#endif

}
#endif

