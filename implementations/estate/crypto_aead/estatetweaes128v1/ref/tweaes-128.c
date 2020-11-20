/*
 * TweAES-128
 * 
 * TweAES-128 is a minor extension of AES-128 [1], the NIST recommended
 * block cipher (based on the Rijndael cipher by Rijmen and Daemen
 * [2,3]), in that it accepts a very short tweak of size 1 nibble.
 * 
 * 1. https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
 * 2. https://web.archive.org/web/20070203204845/https://csrc.nist.gov/
 * 								CryptoToolkit/aes/rijndael/Rijndael.pdf
 * 3. https://link.springer.com/book/10.1007%2F978-3-662-04722-4
 * 
 */
 
#include "estate.h"

/* 
 * No. of bits in the expanded tweak
 * 
 */ 
#define CRYPTO_EXPTWEAKBITS (8)

/* 
 * No. of rounds between tweak injection
 * i.e. tweak is added at intervals of
 * "CRYPTO_TWEAKING_PERIOD" starting at
 * round "CRYPTO_TWEAKING_PERIOD".
 */ 
#define CRYPTO_TWEAKING_PERIOD (2)

/*
 * Multiplication by 2 in GF(8) with respect to the primitive polynomial
 * x^8 + x^4 + x^3 + x + 1
 */
#define _FIELD_MULT_BY_2_IN_GF8(a)		((a&0x80) ? ((a<<1)^0x1b) : (a<<1))

/* 
 * Sbox and its inverse
 */
const u8 _aes_sbox[256] = {
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};
const u8 _aes_sbox_inv[256] = {
	0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
	0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
	0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
	0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
	0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
	0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
	0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
	0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
	0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
	0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
	0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
	0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
	0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
	0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
	0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

/*
 * round constants
 */
const u8 _aes_round_constants[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

/**********************************************************************
 * 
 * @name	:	bytes_to_bits
 * 
 * @note	:	Convert byte oriented "src" to bit oriented "dest".
 * 
 **********************************************************************/
void bytes_to_bits(u8 *dest, const u8 *src, u8 src_len)
{
	for(u8 i=0; i<src_len; i++)
	{
		for(u8 j=0; j<8; j++)
		{
			dest[8*i+j] = (src[i] >> j) & 0x1;
		}
	}
}

/**********************************************************************
 * 
 * @name	:	expand_tweak
 * 
 * @note	:	Expand the 4-bit tweak input in "twk" into a
 * 				CRYPTO_EXPTWEAKBITS-bit expanded tweak in
 * 				"exp_twk".
 * 
 **********************************************************************/
void expand_tweak(u8 *exp_twk, const u8 *twk)
{
	u8 twk_;
	u8 parity = 0x00;
	
	// expand tweak nibble to byte by
	// copying the nibble to another
	twk_ = (twk[0]<<4) ^ twk[0];
	
	// compute parity
	for(u8 i=0; i<4; i++)
	{
		parity ^= ((twk[0]>>i) & 0x1);
	}
	
	if(parity)
	{
		// XOR parity to the second nibble.
		twk_ ^= 0xf0;
	}
	
	// convert expanded tweak to bits
	bytes_to_bits(&exp_twk[0], &twk_, 1);
}

/**********************************************************************
 * 
 * @name	:	generate_round_keys
 * 
 * @note	:	Generate and store the round key bytes using the
 * 				master key.
 * 
 **********************************************************************/
void generate_round_keys(u8 (*round_keys)[16], const u8 *key)
{
    u8 temp[4];
    
    for (u8 i = 0; i < 16; i++)
    {
        round_keys[0][i] = key[i];
    }

    for (u8 i = 0; i < CRYPTO_BC_NUM_ROUNDS; i++)
    {
        // Key bytes 3...0
        temp[3] = _aes_sbox[round_keys[i][12]];
        temp[0] = _aes_sbox[round_keys[i][13]];
        temp[1] = _aes_sbox[round_keys[i][14]];
        temp[2] = _aes_sbox[round_keys[i][15]];
        temp[0] ^= _aes_round_constants[i];
        round_keys[i+1][0] = temp[0] ^ round_keys[i][0];
        round_keys[i+1][1] = temp[1] ^ round_keys[i][1];
        round_keys[i+1][2] = temp[2] ^ round_keys[i][2];
        round_keys[i+1][3] = temp[3] ^ round_keys[i][3];
        
        // Key bytes 7...4
        round_keys[i+1][4] = round_keys[i+1][0] ^ round_keys[i][4];
        round_keys[i+1][5] = round_keys[i+1][1] ^ round_keys[i][5];
        round_keys[i+1][6] = round_keys[i+1][2] ^ round_keys[i][6];
        round_keys[i+1][7] = round_keys[i+1][3] ^ round_keys[i][7];
        
        // Key bytes 11...8
        round_keys[i+1][8] = round_keys[i+1][4] ^ round_keys[i][8];
        round_keys[i+1][9] = round_keys[i+1][5] ^ round_keys[i][9];
        round_keys[i+1][10] = round_keys[i+1][6] ^ round_keys[i][10];
        round_keys[i+1][11] = round_keys[i+1][7] ^ round_keys[i][11];
        
        // Key bytes 15...12
        round_keys[i+1][12] = round_keys[i+1][8] ^ round_keys[i][12];
        round_keys[i+1][13] = round_keys[i+1][9] ^ round_keys[i][13];
        round_keys[i+1][14] = round_keys[i+1][10] ^ round_keys[i][14];
        round_keys[i+1][15] = round_keys[i+1][11] ^ round_keys[i][15];
    }
}

/**********************************************************************
 * 
 * @name	:	sub_bytes
 * 
 * @note	:	SubBytes operation.
 * 
 **********************************************************************/
void sub_bytes(u8 *state_bytes)
{
	for (u8 i=0; i<16; i++)
	{
		state_bytes[i] = _aes_sbox[state_bytes[i]];
	}
}

/**********************************************************************
 * 
 * @name	:	sub_bytes_inv
 * 
 * @note	:	Inverse SubBytes operation.
 * 
 **********************************************************************/
void sub_bytes_inv(u8 *state_bytes)
{
	for (u8 i=0; i<16; i++)
	{
		state_bytes[i] = _aes_sbox_inv[state_bytes[i]];
	}
}

/**********************************************************************
 * 
 * @name	:	shift_rows
 * 
 * @note	:	Shift rows operation.
 * 
 **********************************************************************/
void shift_rows(u8 *state_bytes)
{
    u8 state_;
    
    // first row
    state_ = state_bytes[1];
    state_bytes[1] = state_bytes[5];
    state_bytes[5] = state_bytes[9];
    state_bytes[9] = state_bytes[13];
    state_bytes[13] = state_;
    
    // second row
    state_ = state_bytes[2];
    state_bytes[2] = state_bytes[10];
    state_bytes[10] = state_;
    state_ = state_bytes[6];
    state_bytes[6] = state_bytes[14];
    state_bytes[14] = state_;
    
    // third row
    state_ = state_bytes[15];
    state_bytes[15] = state_bytes[11];
    state_bytes[11] = state_bytes[7];
    state_bytes[7] = state_bytes[3];
    state_bytes[3] = state_;
}

/**********************************************************************
 * 
 * @name	:	shift_rows_inv
 * 
 * @note	:	Inverse shift rows operation.
 * 
 **********************************************************************/
void shift_rows_inv(u8 *state_bytes)
{
    u8 state_;
    
    // first row
    state_ = state_bytes[13];
    state_bytes[13] = state_bytes[9];
    state_bytes[9] = state_bytes[5];
    state_bytes[5] = state_bytes[1];
    state_bytes[1] = state_;
    
    // second row
    state_ = state_bytes[14];
    state_bytes[14] = state_bytes[6];
    state_bytes[6] = state_;
    state_ = state_bytes[10];
    state_bytes[10] = state_bytes[2];
    state_bytes[2] = state_;
    
    // third row
    state_ = state_bytes[3];
    state_bytes[3] = state_bytes[7];
    state_bytes[7] = state_bytes[11];
    state_bytes[11] = state_bytes[15];
    state_bytes[15] = state_;
}

/**********************************************************************
 * 
 * @name	:	mix_columns
 * 
 * @note	:	MixColumns operation.
 * 
 **********************************************************************/
void mix_columns(u8 *state_bytes)
{
	u8 sum;
	u8 temp[4];
	for(u8 i=0; i<16; i+=4)
	{
		sum = state_bytes[i] ^ state_bytes[i+1] ^ state_bytes[i+2] ^ state_bytes[i+3];
		
		temp[0] = _FIELD_MULT_BY_2_IN_GF8((state_bytes[i] ^ state_bytes[i+1]));
		temp[1] = _FIELD_MULT_BY_2_IN_GF8((state_bytes[i+1] ^ state_bytes[i+2]));
		temp[2] = _FIELD_MULT_BY_2_IN_GF8((state_bytes[i+2] ^ state_bytes[i+3]));
		temp[3] = _FIELD_MULT_BY_2_IN_GF8((state_bytes[i+3] ^ state_bytes[i]));
		
		state_bytes[i]   = temp[0] ^ state_bytes[i] ^ sum;
		state_bytes[i+1] = temp[1] ^ state_bytes[i+1] ^ sum;
		state_bytes[i+2] = temp[2] ^ state_bytes[i+2] ^ sum;
		state_bytes[i+3] = temp[3] ^ state_bytes[i+3] ^ sum;
	}
}

/**********************************************************************
 * 
 * @name	:	mix_columns_inv
 * 
 * @note	:	Inverse MixColumns operation.
 * 
 **********************************************************************/
void mix_columns_inv(u8 *state_bytes)
{
	u8 sum;
	u8 temp[7];
	for (u8 i=0; i<16; i+=4)
	{
            sum = state_bytes[i] ^ state_bytes[i+1] ^ state_bytes[i+2] ^ state_bytes[i+3];
            
            temp[0] = _FIELD_MULT_BY_2_IN_GF8((state_bytes[i] ^ state_bytes[i+1]));
            temp[1] = _FIELD_MULT_BY_2_IN_GF8((state_bytes[i+1] ^ state_bytes[i+2]));
            temp[2] = _FIELD_MULT_BY_2_IN_GF8((state_bytes[i+2] ^ state_bytes[i+3]));
            temp[3] = _FIELD_MULT_BY_2_IN_GF8((state_bytes[i+3] ^ state_bytes[i]));
            temp[4] = _FIELD_MULT_BY_2_IN_GF8((_FIELD_MULT_BY_2_IN_GF8((state_bytes[i] ^ state_bytes[i+2]))));
            temp[5] = _FIELD_MULT_BY_2_IN_GF8((_FIELD_MULT_BY_2_IN_GF8((state_bytes[i+1] ^ state_bytes[i+3]))));
            temp[6] = _FIELD_MULT_BY_2_IN_GF8((temp[4] ^ temp[5]));
            
            state_bytes[i]   = sum ^ state_bytes[i]   ^ temp[0];
            state_bytes[i+1] = sum ^ state_bytes[i+1] ^ temp[1];
            state_bytes[i+2] = sum ^ state_bytes[i+2] ^ temp[2];
            state_bytes[i+3] = sum ^ state_bytes[i+3] ^ temp[3];
            
            state_bytes[i]   ^= temp[6] ^ temp[4];
            state_bytes[i+1] ^= temp[6] ^ temp[5];
            state_bytes[i+2] ^= temp[6] ^ temp[4];
            state_bytes[i+3] ^= temp[6] ^ temp[5];
	}
}

/**********************************************************************
 * 
 * @name	:	add_round_key
 * 
 * @note	:	Add round key operation.
 * 
 **********************************************************************/
void add_round_key(u8 *state_bytes, const u8 *round_key_bytes)
{
	//add round key
	for (u8 i=0; i<16; i++)
	{
		state_bytes[i] ^= round_key_bytes[i];
    }
}

/**********************************************************************
 * 
 * @name	:	add_round_tweak
 * 
 * @note	:	Add round tweak operation.
 * 
 **********************************************************************/
void add_round_tweak(u8 *state_bytes, const u8 *exp_twk_bits)
{
	// add round tweak
	for (u8 i=0; i<8; i++)
	{
		state_bytes[i] ^= exp_twk_bits[i];
	}
}

/**********************************************************************
 * 
 * @name	:	tweaes_enc
 * 
 * @note	:	TweAES-128 encryption function.
 * 
 **********************************************************************/
void tweaes_enc(u8 *ct, const u8 (*round_keys)[16], const u8 *twk, const u8 *pt)
{
    u8 exp_twk[CRYPTO_EXPTWEAKBITS] = { 0 };
    
    // expand tweak input if not equal to zero
    if(twk[0] != 0)
	{
		expand_tweak(&exp_twk[0], &twk[0]);
	}
	
    // initial key whitening
    memcpy(&ct[0], &pt[0], 16);
    add_round_key(&ct[0], round_keys[0]);
	
	// intermediate rounds
    for (u8 r=1; r<CRYPTO_BC_NUM_ROUNDS; r++)
    {
		sub_bytes(&ct[0]);
        shift_rows(&ct[0]);
        mix_columns(&ct[0]);
		add_round_key(&ct[0], round_keys[r]);
		if(r%CRYPTO_TWEAKING_PERIOD == 0)
		{
			add_round_tweak(&ct[0], &exp_twk[0]);
		}
    }
    
    // last round
    sub_bytes(&ct[0]);
    shift_rows(&ct[0]);
    add_round_key(&ct[0], round_keys[10]);
}

/**********************************************************************
 * 
 * @name	:	tweaes_dec
 * 
 * @note	:	TweAES-128 decryption function.
 * 
 **********************************************************************/
void tweaes_dec(u8 *pt, const u8 (*round_keys)[16], const u8 *twk, const u8 *ct)
{
    u8 exp_twk[CRYPTO_EXPTWEAKBITS] = { 0 };
    
    // expand tweak input if not equal to zero
    if(twk[0] != 0)
	{
		expand_tweak(&exp_twk[0], &twk[0]);
	}
   
	// first round
    memcpy(&pt[0], &ct[0], 16);
    add_round_key(&pt[0], round_keys[10]);
    shift_rows_inv(&pt[0]);
    sub_bytes_inv(&pt[0]);
	
	// intermediate rounds
    for (u8 r,i=1; i<CRYPTO_BC_NUM_ROUNDS; i++)
    {
		r = CRYPTO_BC_NUM_ROUNDS-i;
		if(r%CRYPTO_TWEAKING_PERIOD == 0)
		{
			add_round_tweak(&pt[0], &exp_twk[0]);
		}
		add_round_key(&pt[0], round_keys[r]);
		mix_columns_inv(&pt[0]);
		shift_rows_inv(&pt[0]);
		sub_bytes_inv(&pt[0]);
    }
    
    // last round
    add_round_key(&pt[0], round_keys[0]);
}
