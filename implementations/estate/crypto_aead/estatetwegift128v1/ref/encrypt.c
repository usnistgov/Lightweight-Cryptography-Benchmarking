/*
 * ESTATE_TweGIFT-128
 * 
 * 
 * ESTATE_TweGIFT-128 ia a determinsitic AEAD based on the ESTATE mode
 * of operation and TweGIFT-128 tweakable block cipher.
 * 
 * Test Vector (in little endian format):
 * Key	: 0f 0e 0d 0c 0b 0a 09 08 07 06 05 04 03 02 01 00
 * Nonce: 0f 0e 0d 0c 0b 0a 09 08 07 06 05 04 03 02 01 00
 * PT 	:
 * AD	: 
 * CT	: 11 72 72 64 33 68 7E 51 51 01 5E D2 BB 76 ED 36
 * 
 */

#include "crypto_aead.h"
#include "api.h"
#include "estate.h"

/**********************************************************************
 * 
 * @name	:	xor_bytes
 * 
 * @note	:	XORs "num" many bytes of "src" to "dest".
 * 
 **********************************************************************/		
static void xor_bytes(u8 *dest, const u8 *src, u8 num)
{
	for(u8 i=0; i < num; i++)
	{
		dest[i] ^= src[i];
	}
}

/**********************************************************************
 * 
 * @name	:	memcpy_and_zero_one_pad
 * 
 * @note	:	Copies src bytes to dest and pads with 10* to create
 * 				CRYPTO_BLOCKBYTES-oriented data.
 * 
 **********************************************************************/
static void memcpy_and_zero_one_pad(u8* dest, const u8 *src, u8 len)
{
	memset(dest, 0, CRYPTO_BLOCKBYTES);
	memcpy(dest, src, len);
	dest[len] ^= 0x01;
}

/**********************************************************************
 * 
 * @name	:	fcbc_star
 * 
 * @note	:	FCBC* processing of input with some iv given in tag
 * 				itself.
 * 
 **********************************************************************/
static void fcbc_star(u8 *tag, const u8 (*round_keys)[32], const u8 *in, const u64 inlen, const u64 in_blocks, const u8 *twks)
{
	u8 zero = 0x00;
	u8 temp[CRYPTO_BLOCKBYTES];
	
	// process intermediate blocks with zero tweak value
	for(u64 j=0; j<in_blocks-1; j++)
	{
		// compute T = E^0(K,T+I_j)
		memcpy(temp, tag, CRYPTO_BLOCKBYTES);
		xor_bytes(temp, &in[j*CRYPTO_BLOCKBYTES], CRYPTO_BLOCKBYTES);
		twegift_enc(tag, &round_keys[0], &zero, temp);
	}
	
	// process last block with distinct tweak
	// tweak value depends on whether block is partial or full
	if(PARTIAL_BLOCK_LEN(in_blocks,inlen) != CRYPTO_BLOCKBYTES)
	{
		// compute T = E^3/5/7(K,T+I_{i-1})
		memcpy_and_zero_one_pad(temp, &in[(in_blocks-1)*CRYPTO_BLOCKBYTES], PARTIAL_BLOCK_LEN(in_blocks, inlen));
		xor_bytes(temp, tag, CRYPTO_BLOCKBYTES);
		twegift_enc(tag, &round_keys[0], &twks[1], temp);
	}
	else
	{
		// compute T = E^2/4/6(K,T+I_{i-1})
		memcpy(temp, tag, CRYPTO_BLOCKBYTES);
		xor_bytes(temp, &in[(in_blocks-1)*CRYPTO_BLOCKBYTES], CRYPTO_BLOCKBYTES);
		twegift_enc(tag, &round_keys[0], &twks[0], temp);
	}
}

/**********************************************************************
 * 
 * @name	:	mac
 * 
 * @note	:	Tag generator.
 * 
 **********************************************************************/
static void mac(u8 *tag, const u8 (*round_keys)[32], const u8 *nonce, const u8 *ad, const u64 adlen, const u64 ad_blocks, const u8 *pt, const u64 ptlen, const u64 pt_blocks)
{
	u8 twks[2] = { 0 };
	u8 temp[CRYPTO_NPUBBYTES];
	memcpy(temp, nonce, CRYPTO_BLOCKBYTES);
 	
 	memset(tag, 0x00, CRYPTO_ABYTES);
 	
	if(adlen == 0 && ptlen == 0)
	{
		// generate tag when both ad and pt are empty
		twks[0] = 0x08;
		twegift_enc(&tag[0], &round_keys[0], &twks[0], &temp[0]);
	}
	
	// generate tag when ad and/or pt are non-empty
	twks[0] = 0x01;
	twegift_enc(&tag[0], &round_keys[0], &twks[0], &temp[0]);
	
	if(adlen > 0)
	{
		// process ad blocks
		twks[0] = ptlen != 0 ? 0x02 : 0x06;
		twks[1] = ptlen != 0 ? 0x03 : 0x07;
		fcbc_star(&tag[0], &round_keys[0], ad, adlen, ad_blocks, &twks[0]);
	}
	
	if(ptlen > 0)
	{
		// process pt blocks
		twks[0] = 0x04;
		twks[1] = 0x05;
		fcbc_star(&tag[0], &round_keys[0], pt, ptlen, pt_blocks, &twks[0]);
	}
	
}

/**********************************************************************
 * 
 * @name	:	ofb
 * 
 * @note	:	Ciphertext generation using OFB module.
 * 
 **********************************************************************/
static void ofb(u8 *out, u64 *outlen, const u8 (*round_keys)[32], const u8 *iv, const u8 *in, const u64 inlen, const u64 in_blocks)
{
	u8 twk = 0x00;
	
	u8 iv_[CRYPTO_BLOCKBYTES];
	u8 temp[CRYPTO_BLOCKBYTES];

	*outlen = 0;
	
	// process non-last blocks
	memcpy(iv_, iv, CRYPTO_BLOCKBYTES);
	for(u8 i=0; i<in_blocks-1; i++)
	{
		memcpy(temp, iv_, CRYPTO_BLOCKBYTES);
		twegift_enc(iv_, &round_keys[0], &twk, temp);
		memcpy(&out[i*CRYPTO_BLOCKBYTES], &in[i*CRYPTO_BLOCKBYTES], CRYPTO_BLOCKBYTES);
		xor_bytes(&out[i*CRYPTO_BLOCKBYTES], iv_, CRYPTO_BLOCKBYTES);
		*outlen += CRYPTO_BLOCKBYTES;
	}
	
	// last block processing
	// iv = E^0(K,iv)
	memcpy(temp, iv_, CRYPTO_BLOCKBYTES);
	twegift_enc(iv_, &round_keys[0], &twk, temp);
	
	// last block could be partial
	// C_{m-1} = M_{m-1} + chop(iv)
	memcpy(&out[(in_blocks-1)*CRYPTO_BLOCKBYTES], &in[(in_blocks-1)*CRYPTO_BLOCKBYTES], PARTIAL_BLOCK_LEN(in_blocks, inlen));
	xor_bytes(&out[(in_blocks-1)*CRYPTO_BLOCKBYTES], iv_, PARTIAL_BLOCK_LEN(in_blocks, inlen));
	*outlen += PARTIAL_BLOCK_LEN(in_blocks, inlen);
}

/**********************************************************************
 * 
 * @name	:	crypto_aead_encrypt
 * 
 * @note	:	Main encryption function.
 * 
 **********************************************************************/
int crypto_aead_encrypt(
	unsigned char *ct, unsigned long long *ctlen,
	const unsigned char *pt, unsigned long long ptlen,
	const unsigned char *ad, unsigned long long adlen,
	const unsigned char *nsec,
	const unsigned char *npub,
	const unsigned char *k
)
{
	// to bypass unused
	// warning on nsec
	nsec = nsec;
	
	u8 tag[CRYPTO_ABYTES] = { 0 };
	
	// initialize and generate round keys
	u64 pt_blocks = ptlen%CRYPTO_BLOCKBYTES ? ((ptlen/CRYPTO_BLOCKBYTES)+1) : (ptlen/CRYPTO_BLOCKBYTES);
	u64 ad_blocks = adlen%CRYPTO_BLOCKBYTES ? ((adlen/CRYPTO_BLOCKBYTES)+1) : (adlen/CRYPTO_BLOCKBYTES);
	
	u8 round_keys[CRYPTO_BC_NUM_ROUNDS][32];
	_TWEGIFT_ENC_ROUND_KEY_GEN(&round_keys[0], &k[0]);
	
	// generate tag
	mac(&tag[0], &round_keys[0], npub, ad, adlen, ad_blocks, pt, ptlen, pt_blocks);
	
	// generate ciphertext
	if(pt_blocks != 0)
	{
		ofb(ct, ctlen, &round_keys[0], &tag[0], pt, ptlen, pt_blocks);
	}
	else
	{
		*ctlen = 0;
	}
	// append tag to ciphertext
	memcpy(&ct[*ctlen],&tag[0],CRYPTO_ABYTES);
	*ctlen += CRYPTO_ABYTES;
	
	return 0;
}

/**********************************************************************
 * 
 * @name	:	crypto_aead_decrypt
 * 
 * @note	:	Main decryption function.
 * 
 **********************************************************************/
int crypto_aead_decrypt(
	unsigned char *pt, unsigned long long *ptlen,
	unsigned char *nsec,
	const unsigned char *ct, unsigned long long ctlen,
	const unsigned char *ad, unsigned long long adlen,
	const unsigned char *npub,
	const unsigned char *k
)
{
	int pass = 0;
	
	// to bypass unused
	// warning on nsec
	nsec = nsec;
	
	u8 tag[CRYPTO_ABYTES] = { 0 };
	
	// extract tag (to be used as IV for OFB mode) from ciphertext.
	// reflect the change in ciphertext length
	memcpy(&tag[0], &ct[ctlen-CRYPTO_ABYTES], CRYPTO_ABYTES);
	ctlen -= CRYPTO_ABYTES;
	
	// initialize and generate round keys
	u64 ct_blocks = ctlen%CRYPTO_BLOCKBYTES ? ((ctlen/CRYPTO_BLOCKBYTES)+1) : (ctlen/CRYPTO_BLOCKBYTES);
	u64 ad_blocks = adlen%CRYPTO_BLOCKBYTES ? ((adlen/CRYPTO_BLOCKBYTES)+1) : (adlen/CRYPTO_BLOCKBYTES);
	
	u8 round_keys[CRYPTO_BC_NUM_ROUNDS][32];
	_TWEGIFT_ENC_ROUND_KEY_GEN(&round_keys[0], &k[0]);
	
	// generate plaintext
	if(ct_blocks != 0)
	{
		ofb(pt, ptlen, &round_keys[0], &tag[0], ct, ctlen, ct_blocks);
	}
	else
	{
		*ptlen = 0;
	}
	
	// generate tag
	u64 pt_blocks = *ptlen%CRYPTO_BLOCKBYTES ? ((*ptlen/CRYPTO_BLOCKBYTES)+1) : (*ptlen/CRYPTO_BLOCKBYTES);
	mac(&tag[0], &round_keys[0], npub, ad, adlen, ad_blocks, pt, *ptlen, pt_blocks);

	// check computed tag =? received tag (0 if equal)
	pass = memcmp(tag, &ct[*ptlen], CRYPTO_ABYTES);
	
	if(!pass)
	{
		return pass;
	}
	else
	{
		return -1;
	}
}
