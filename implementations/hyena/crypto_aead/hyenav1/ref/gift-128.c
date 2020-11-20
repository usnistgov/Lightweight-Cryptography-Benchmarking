/*
 * GIFT-128
 * 
 * GIFT-128 is a lightweight block cipher (by Banik et al. [1,2]). We
 * have reused the reference code for GIFT-128-128 (available at [3]) by
 * the GIFT team.
 * 
 * 1. https://link.springer.com/chapter/10.1007/978-3-319-66787-4_16
 * 2. https://eprint.iacr.org/2017/622.pdf
 * 3. https://sites.google.com/view/giftcipher/ 
 * 
 * The main modification from our side is some minor code cleaning and
 * restructuring in order to make the code consistent with our
 * notations and conventions.
 * 
 */

#include "hyena.h"

/* 
 * Sbox and its inverse
 */ 
const u8 _gift_sbox[16] = { 1, 10, 4, 12, 6, 15, 3, 9, 2, 13, 11, 7, 5, 0, 8, 14 };
const u8 _gift_sbox_inv[16] = { 13, 0, 8, 6, 2, 12, 4, 11, 14, 7, 1, 10, 3, 9, 15, 5 };

/*
 * bit permutation and its inverse
 */ 
const u8 _gift_perm[] = {
	0, 33, 66, 99, 96, 1, 34, 67, 64, 97, 2, 35, 32, 65, 98, 3,
	4, 37, 70, 103, 100, 5, 38, 71, 68, 101, 6, 39, 36, 69, 102, 7,
	8, 41, 74, 107, 104,  9, 42, 75, 72, 105, 10, 43, 40, 73, 106, 11,
	12, 45, 78, 111, 108, 13, 46, 79, 76, 109, 14, 47, 44, 77, 110, 15,
	16, 49, 82, 115, 112, 17, 50, 83, 80, 113, 18, 51, 48, 81, 114, 19,
	20, 53, 86, 119, 116, 21, 54, 87, 84, 117, 22, 55, 52, 85, 118, 23,
	24, 57, 90, 123, 120, 25, 58, 91, 88, 121, 26, 59, 56, 89, 122, 27,
	28, 61, 94, 127, 124, 29, 62, 95, 92, 125, 30, 63, 60, 93, 126, 31
};
const u8 _gift_perm_inv[] = {
	0, 5, 10, 15, 16, 21, 26, 31, 32, 37, 42, 47, 48, 53, 58, 63,
	64, 69, 74, 79, 80, 85, 90, 95, 96, 101, 106, 111, 112, 117, 122, 127,
	12, 1, 6, 11, 28, 17, 22, 27, 44, 33, 38, 43, 60, 49, 54, 59,
	76, 65, 70, 75, 92, 81, 86, 91, 108, 97, 102, 107, 124, 113, 118, 123,
	8, 13, 2, 7, 24, 29, 18, 23, 40, 45, 34, 39, 56, 61, 50, 55,
	72, 77, 66, 71, 88, 93, 82, 87,104,109, 98,103,120,125,114,119,
	4, 9, 14, 3, 20, 25, 30, 19, 36, 41, 46, 35, 52, 57, 62, 51,
	68, 73, 78, 67, 84, 89, 94, 83, 100, 105, 110, 99, 116, 121, 126, 115
};

/*
 * round constants
 */ 
const u8 _gift_round_constants[62] = {
    0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3E, 0x3D, 0x3B, 0x37, 0x2F,
    0x1E, 0x3C, 0x39, 0x33, 0x27, 0x0E, 0x1D, 0x3A, 0x35, 0x2B,
    0x16, 0x2C, 0x18, 0x30, 0x21, 0x02, 0x05, 0x0B, 0x17, 0x2E,
    0x1C, 0x38, 0x31, 0x23, 0x06, 0x0D, 0x1B, 0x36, 0x2D, 0x1A,
    0x34, 0x29, 0x12, 0x24, 0x08, 0x11, 0x22, 0x04, 0x09, 0x13,
    0x26, 0x0c, 0x19, 0x32, 0x25, 0x0a, 0x15, 0x2a, 0x14, 0x28,
    0x10, 0x20
};

/**********************************************************************
 * 
 * @name	:	bytes_to_nibbles
 * 
 * @note	:	Convert byte oriented "src" to nibble oriented "dest".
 * 
 **********************************************************************/
void bytes_to_nibbles(u8 *dest, const u8 *src, u8 src_len)
{
    for(u8 i=0; i<src_len; i++)
    {
        dest[2*i] = src[i]&0xF;
        dest[2*i+1] = (src[i]&0xF0)>>4;
    }
}

/**********************************************************************
 * 
 * @name	:	nibbles_to_bytes
 * 
 * @note	:	Convert nibble oriented "src" to byte oriented "dest".
 * 
 **********************************************************************/
void nibbles_to_bytes(u8 *dest, const u8 *src, u8 dest_len)
{
    for(u8 i=0; i<dest_len; i++)
	{
		dest[i] = src[2*i+1]<<4 | src[2*i];
	}
}

/**********************************************************************
 * 
 * @name	:	nibbles_to_bits
 * 
 * @note	:	Convert nibble oriented "src" to bit oriented "dest".
 * 
 **********************************************************************/
void nibbles_to_bits(u8 *dest, const u8 *src, u8 src_len)
{
	for(u8 i=0; i<src_len; i++)
	{
		for(u8 j=0; j<4; j++)
		{
			dest[4*i+j] = (src[i] >> j) & 0x1;
		}
	}
}

/**********************************************************************
 * 
 * @name	:	bits_to_nibbles
 * 
 * @note	:	Convert bit oriented "src" to nibble oriented "dest".
 * 
 **********************************************************************/
void bits_to_nibbles(u8 *dest, const u8 *src, u8 dest_len)
{
    for(u8 i=0; i<dest_len; i++)
	{
		dest[i]=0;
		for(u8 j=0; j<4; j++)
		{
			 dest[i] ^= src[4*i+j] << j;
		}
	}
}

/**********************************************************************
 * 
 * @name	:	generate_round_keys
 * 
 * @note	:	Generate and store the round key nibbles using the
 * 				master key.
 * 
 **********************************************************************/
void generate_round_keys(u8 (*round_key_nibbles)[32], const u8 *key_bytes)
{
	u8 key_nibbles[32];
	//memcpy(&key_nibbles_[0], &key_nibbles[0], 32);
	
	// convert master key from byte-oriented
	// to nibble-oriented
	bytes_to_nibbles(key_nibbles, key_bytes, 16);
	
	//copy the first round key
	for (u8 i=0; i<32; i++)
	{
		round_key_nibbles[0][i] = key_nibbles[i];
	}
	
	// update round key and store the rest of the round keys
	u8 temp[32];
	for (u8 r=1; r<CRYPTO_BC_NUM_ROUNDS; r++)
	{
		//key update
		//entire key>>32
		for(u8 i=0; i<32; i++)
		{
			temp[i] = key_nibbles[(i+8)%32];
		}
		for(u8 i=0; i<24; i++)
		{
			key_nibbles[i] = temp[i];
		}
		//k0>>12
		key_nibbles[24] = temp[27];
		key_nibbles[25] = temp[24];
		key_nibbles[26] = temp[25];
		key_nibbles[27] = temp[26];
		//k1>>2
		key_nibbles[28] = ((temp[28]&0xc)>>2) ^ ((temp[29]&0x3)<<2);
		key_nibbles[29] = ((temp[29]&0xc)>>2) ^ ((temp[30]&0x3)<<2);
		key_nibbles[30] = ((temp[30]&0xc)>>2) ^ ((temp[31]&0x3)<<2);
		key_nibbles[31] = ((temp[31]&0xc)>>2) ^ ((temp[28]&0x3)<<2);
		
		//copy the key state
		for (u8 i=0; i<32; i++)
		{
			round_key_nibbles[r][i] = key_nibbles[i];
		}
	}
}

/**********************************************************************
 * 
 * @name	:	sub_cells
 * 
 * @note	:	SubCells operation.
 * 
 **********************************************************************/
void sub_cells(u8 *state_nibbles)
{
	for(u8 i=0; i<32; i++)
	{
		state_nibbles[i] = _gift_sbox[state_nibbles[i]];
	}
}

/**********************************************************************
 * 
 * @name	:	sub_cells_inv
 * 
 * @note	:	Inverse SubCells operation.
 * 
 **********************************************************************/
void sub_cells_inv(u8 *state_nibbles)
{
	for(u8 i=0; i<32; i++)
	{
		state_nibbles[i] = _gift_sbox_inv[state_nibbles[i]];
	}
}

/**********************************************************************
 * 
 * @name	:	perm_bits
 * 
 * @note	:	PermBits operation.
 * 
 **********************************************************************/
void perm_bits(u8 *state_bits)
{	
	//nibbles to bits
	u8 bits[128];
	
	//permute the bits
	for(u8 i=0; i<128; i++)
	{
		bits[_gift_perm[i]] = state_bits[i];
	}
	memcpy(&state_bits[0], &bits[0], 128);
}

/**********************************************************************
 * 
 * @name	:	perm_bits_inv
 * 
 * @note	:	Inverse PermBits operation.
 * 
 **********************************************************************/
void perm_bits_inv(u8 *state_bits)
{	
	//nibbles to bits
	u8 bits[128];
	
	//permute the bits
	for(u8 i=0; i<128; i++)
	{
		bits[_gift_perm_inv[i]] = state_bits[i];
	}
	memcpy(&state_bits[0], &bits[0], 128);
}

/**********************************************************************
 * 
 * @name	:	add_round_key
 * 
 * @note	:	Add round key operation.
 * 
 **********************************************************************/
void add_round_key(u8 *state_bits, const u8 *round_key_nibbles)
{		
	//round key nibbles to bits
	u8 key_bits[128];
	nibbles_to_bits(&key_bits[0], &round_key_nibbles[0], 32);

	//add round key
	for (u8 i=0; i<32; i++){
		state_bits[4*i+1] ^= key_bits[i];
		state_bits[4*i+2] ^= key_bits[i+64];
	}
}

/**********************************************************************
 * 
 * @name	:	add_round_constant
 * 
 * @note	:	Add round constant operation.
 * 
 **********************************************************************/
void add_round_constants(u8 *state_bits, u8 round)
{
	//add constant
	state_bits[3] ^= _gift_round_constants[round] & 0x1;
	state_bits[7] ^= (_gift_round_constants[round]>>1) & 0x1;
	state_bits[11] ^= (_gift_round_constants[round]>>2) & 0x1;
	state_bits[15] ^= (_gift_round_constants[round]>>3) & 0x1;
	state_bits[19] ^= (_gift_round_constants[round]>>4) & 0x1;
	state_bits[23] ^= (_gift_round_constants[round]>>5) & 0x1;
	state_bits[127] ^= 1;
}

/**********************************************************************
 * 
 * @name	:	gift_enc
 * 
 * @note	:	GIFT-128 encryption function.
 * 
 **********************************************************************/
void gift_enc(u8 *ct, const u8 (*round_keys)[32], const u8 *pt)
{
    u8 in[32];
    
	// convert input plaintext from
	// byte-oriented to nibble-oriented
	bytes_to_nibbles(&in[0], &pt[0], 16);
    
	u8 in_bits[128];
	
	for(u8 r=0; r < CRYPTO_BC_NUM_ROUNDS; r++)
	{
		// subcells operation
		sub_cells(&in[0]);

		// permbits operation
		nibbles_to_bits(&in_bits[0], &in[0], 32);
		perm_bits(&in_bits[0]);
		
		// addroundkey operation
		add_round_key(&in_bits[0], round_keys[r]);
		
		// addroundconstant operation
		add_round_constants(&in_bits[0], r);
		
		// input bits to nibbles
		bits_to_nibbles(&in[0], &in_bits[0], 32);
	}
	
	//convert ciphertext from nibble-oriented to byte-oriented
	nibbles_to_bytes(ct, in, 16);
}
