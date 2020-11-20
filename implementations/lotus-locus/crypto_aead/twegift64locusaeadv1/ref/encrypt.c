/*
 * TweGIFT-64_LOCUS-AEAD
 * 
 * 
 * TweGIFT-64_LOCUS-AEAD ia a nonce-based AEAD based on the LOCUS-AEAD
 * mode of operation and TweGIFT-64 tweakable block cipher.
 * 
 * Test Vector (in little endian format):
 * Key	: 0f 0e 0d 0c 0b 0a 09 08 07 06 05 04 03 02 01 00
 * PT 	:
 * AD	: 
 * CT	: e8 8d f3 3f b8 eb f3 37
 * 
 */

#include "crypto_aead.h"
#include "api.h"
#include "locus.h"

/**********************************************************************
 * 
 * @name	:	xor_bytes
 * 
 * @note	:	XORs "num" many bytes of "src" to "dest".
 * 
 **********************************************************************/		
void xor_bytes(u8 *dest, const u8 *src, u8 num)
{
	for(u8 i=0; i < num; i++)
	{
		dest[i] ^= src[i];
	}
}

/**********************************************************************
 * 
 * @name	:	mult_by_alpha
 * 
 * @note	:	Multiplies given field element in "src" with \alpha,
 * 				the primitive element corresponding to the primitive
 * 				polynomial p(x) as defined in PRIM_POLY_MOD_128, and
 * 				stores the result in "dest".
 * 
 **********************************************************************/	
void mult_by_alpha(u8 *dest, u8 *src)
{
	u8 mask = 0x00;
	if(src[CRYPTO_KEYBYTES-1] & 0x80){
		mask = PRIM_POLY_MOD_128;
	}
	for(u8 i=CRYPTO_KEYBYTES-1; i>0; i--){
		dest[i] = src[i]<<1 | src[i-1]>>7;
	}
	dest[0] = src[0]<<1;
	dest[0] ^= mask;
}

/**********************************************************************
 * 
 * @name	:	memcpy_and_zero_one_pad
 * 
 * @note	:	Copies src bytes to dest and pads with 10* to create
 * 				CRYPTO_BLOCKBYTES-oriented data.
 * 
 **********************************************************************/
void memcpy_and_zero_one_pad(u8* dest, const u8 *src, u8 len)
{
	memset(dest, 0, CRYPTO_BLOCKBYTES);
	memcpy(dest, src, len);
	dest[len] ^= 0x01;
}

/**********************************************************************
 * 
 * @name	:	init
 * 
 * @note	:	Derives nonce-dependent key and mask.
 * 
 **********************************************************************/

// CC - Changing function name due to a conflict with the Arduino init() function
void Init(u8 *nonced_key, u8 *nonced_mask, const u8 *key, const u8 *nonce)
{
	u8 twk;
	
	u8 zero[CRYPTO_BLOCKBYTES] = { 0 };
	
	u8 enc_zero[CRYPTO_BLOCKBYTES];
	
	// set control bits to 000.
	twk = 0x00;
	
	// encrypt zero with the master key.
	twegift_enc(enc_zero, key, &twk, zero);
	
	// compute K_N = K + N
	memcpy(nonced_key, key, CRYPTO_KEYBYTES);
	xor_bytes(nonced_key, nonce, CRYPTO_NPUBBYTES);
	
	// set control bits to 001.
	twk = 0x01;
	
	//compute \Delta_N = E^1_{K_N}(E^0_K(0))
	twegift_enc(nonced_mask, nonced_key, &twk, enc_zero);
}

/**********************************************************************
 * 
 * @name	:	proc_ad
 * 
 * @note	:	Processes associated data to generate intermediate
 * 				checksum.
 * 
 **********************************************************************/
void proc_ad(u8 *nonced_key, u8 *vxor, u8 *nonced_mask, const u8 *ad, u64 a, u64 adlen)
{
	u8 twk;
	
	u8 u[CRYPTO_BLOCKBYTES];
	
	u8 v[CRYPTO_BLOCKBYTES];
	
	// set control bits to 010
	twk = 0x02;
	
	// L_0 = K_N \odot \alpha
	mult_by_alpha(nonced_key, nonced_key);
	
	for(u64 i=0; i < a-1; i++)
	{
		// compute U_i = A_i + \Delta_N 
		memcpy(&u[0],&ad[i*CRYPTO_BLOCKBYTES],CRYPTO_BLOCKBYTES);
		xor_bytes(u, nonced_mask, CRYPTO_BLOCKBYTES);
		
		// compute V_i = E^2_{L_i}(U_i)
		twegift_enc(v, nonced_key, &twk, u);
		
		// V_\xor = V_\xor + V_i
		xor_bytes(vxor, v, CRYPTO_BLOCKBYTES);
		
		// L_{i+1} = L_i \odot \alpha
		mult_by_alpha(nonced_key, nonced_key);
	}
	if(adlen%CRYPTO_BLOCKBYTES != 0)
	{
		//partial block processing
		
		// set control bits to 011
		twk = 0x03;
		
		// compute U_{a-1} = 0^*1||A_{a-1} + \Delta_N
		memcpy_and_zero_one_pad(&u[0], &ad[(a-1)*CRYPTO_BLOCKBYTES], PARTIAL_BLOCK_LEN(a,adlen));
		xor_bytes(u, nonced_mask, CRYPTO_BLOCKBYTES);
	}
	else
	{
		// full block processing
		
		// compute U_{a-1} = A_{a-1} + \Delta_N
		memcpy(&u[0], &ad[(a-1)*CRYPTO_BLOCKBYTES], CRYPTO_BLOCKBYTES);
		xor_bytes(u, nonced_mask, CRYPTO_BLOCKBYTES);
	}
	
	// compute V_{a-1} = E^2/3_{L_{a-1}}(U_{a-1})
	twegift_enc(v, nonced_key, &twk, u);
	
	// V_\xor = V_\xor + V_i
	xor_bytes(vxor, v, CRYPTO_BLOCKBYTES);
}

/**********************************************************************
 * 
 * @name	:	proc_pt
 * 
 * @note	:	Generates ciphertext by encrypting plaintext.
 * 
 **********************************************************************/
void proc_pt(u8 *nonced_key, u8 *wxor, u8 *ct, u64 *ctlen, u8 *nonced_mask, const u8 *pt, u64 m, u64 ptlen)
{
	u8 twk;
	
	u8 x[CRYPTO_BLOCKBYTES];
	
	u8 w[CRYPTO_BLOCKBYTES];
	
	u8 y[CRYPTO_BLOCKBYTES];
	
	*ctlen = 0;
	
	// set control bits to 100
	twk = 0x04;
	
	// L_a = K_N \odot \alpha
	mult_by_alpha(nonced_key, nonced_key);
	
	for(u64 i=0; i < m-1; i++)
	{
		// compute X_{i} = M_i + \Delta_N
		memcpy(&x[0], &pt[i*CRYPTO_BLOCKBYTES], CRYPTO_BLOCKBYTES);
		xor_bytes(x, nonced_mask, CRYPTO_BLOCKBYTES);
		
		// compute W_{i} = E^4_{L_{a+i}}(X_{i})
		twegift_enc(w, nonced_key, &twk, x);
		
		// W_\xor = W_\xor + W_{i}
		xor_bytes(wxor, w, CRYPTO_BLOCKBYTES);
		
		// compute Y_{i} = E^4_{L_{a+i}}(W_{i})
		twegift_enc(y, nonced_key, &twk, w);
		
		// compute C_{i} = Y_{i} + \Delta_N
		xor_bytes(y, nonced_mask, CRYPTO_BLOCKBYTES);
		memcpy(&ct[i*CRYPTO_BLOCKBYTES], &y[0], CRYPTO_BLOCKBYTES);
		*ctlen += CRYPTO_BLOCKBYTES;
		
		// L_{a+i+1} = L_{a+i} \odot \alpha
		mult_by_alpha(nonced_key, nonced_key);
	}
	// set control bits to 101
	twk = 0x05;
	
	// compute X_{m-1} = \Delta_N + <|M|-(m-1)n>_n
	memcpy(x, nonced_mask, CRYPTO_BLOCKBYTES);
	x[0] ^= PARTIAL_BLOCK_LEN(m, ptlen);
	
	// compute W_{m-1} = E^5_{L_{a+m-1}}(X_{m-1})
	twegift_enc(w, nonced_key, &twk, x);
	
	// compute Y_{m-1} = E^5_{L_{a+m-1}}(W_{m-1})
	twegift_enc(y, nonced_key, &twk, w);
	
	// compute C_{m-1} = chop(Y_{m-1} + \Delta_N) + M_{m-1}
	xor_bytes(y, nonced_mask, CRYPTO_BLOCKBYTES);
	memcpy(&ct[(m-1)*CRYPTO_BLOCKBYTES], &pt[(m-1)*CRYPTO_BLOCKBYTES], PARTIAL_BLOCK_LEN(m, ptlen));
	xor_bytes(&ct[(m-1)*CRYPTO_BLOCKBYTES], y, PARTIAL_BLOCK_LEN(m, ptlen));
	*ctlen += PARTIAL_BLOCK_LEN(m, ptlen);
	
	// W_\xor = W_\xor + W_{m-1} + M_{m-1}
	xor_bytes(wxor, w, CRYPTO_BLOCKBYTES);
	xor_bytes(wxor, &pt[(m-1)*CRYPTO_BLOCKBYTES], PARTIAL_BLOCK_LEN(m, ptlen));
}

/**********************************************************************
 * 
 * @name	:	proc_ct
 * 
 * @note	:	Generates plaintext by decrypting ciphertext.
 * 
 **********************************************************************/
void proc_ct(u8 *nonced_key, u8 *wxor, u8 *pt, u64 *ptlen, u8 *nonced_mask, const u8 *ct, u64 m, u64 ctlen)
{
	u8 twk;
	
	u8 x[CRYPTO_BLOCKBYTES];
	
	u8 w[CRYPTO_BLOCKBYTES];
	
	u8 y[CRYPTO_BLOCKBYTES];
	
	*ptlen = 0;
	
	// set control bits to 100
	twk = 0x04;
	
	// L_a = K_N \odot \alpha
	mult_by_alpha(nonced_key, nonced_key);
	
	for(u64 i=0; i < m-1; i++)
	{
		// compute Y_{i} = C_i + \Delta_N
		memcpy(&y[0], &ct[i*CRYPTO_BLOCKBYTES], CRYPTO_BLOCKBYTES);
		xor_bytes(y, nonced_mask, CRYPTO_BLOCKBYTES);
		
		// compute W_{i} = E^-4_{L_{a+i}}(Y_{i})
		twegift_dec(w, nonced_key, &twk, y);
		
		// W_\xor = W_\xor + W_{i}
		xor_bytes(wxor, w, CRYPTO_BLOCKBYTES);
		
		// compute X_{i} = E^-4_{L_{a+i}}(W_{i})
		twegift_dec(x, nonced_key, &twk, w);
		
		// compute M_{i} = X_{i} + \Delta_N
		xor_bytes(x, nonced_mask, CRYPTO_BLOCKBYTES);
		memcpy(&pt[i*CRYPTO_BLOCKBYTES], &x[0], CRYPTO_BLOCKBYTES);
		*ptlen += CRYPTO_BLOCKBYTES;
		
		// L_{a+i+1} = L_{a+i} \odot \alpha
		mult_by_alpha(nonced_key, nonced_key);
	}
	// set control bits to 101
	twk = 0x05;
	
	// compute X_{m-1} = \Delta_N + <|C|-(m-1)n>_n
	memset(x, 0, CRYPTO_BLOCKBYTES);
	x[0] = PARTIAL_BLOCK_LEN(m, ctlen);
	xor_bytes(x, nonced_mask, CRYPTO_BLOCKBYTES);
	
	// compute W_{m-1} = E^5_{L_{a+m-1}}(X_{m-1})
	twegift_enc(w, nonced_key, &twk, x);
	
	// compute Y_{m-1} = E^5_{L_{a+m-1}}(W_{m-1})
	twegift_enc(y, nonced_key, &twk, w);
	
	// compute M_{m-1} = chop(Y_{m-1} + \Delta_N) + C_{m-1}
	xor_bytes(y, nonced_mask, CRYPTO_BLOCKBYTES);
	memcpy(&pt[(m-1)*CRYPTO_BLOCKBYTES], &ct[(m-1)*CRYPTO_BLOCKBYTES], PARTIAL_BLOCK_LEN(m, ctlen));
	xor_bytes(&pt[(m-1)*CRYPTO_BLOCKBYTES], y, PARTIAL_BLOCK_LEN(m, ctlen));
	*ptlen += PARTIAL_BLOCK_LEN(m, ctlen);
	
	// W_\xor = W_\xor \xor W_{m-1} \xor M_{m-1}
	xor_bytes(wxor, w, CRYPTO_BLOCKBYTES);
	xor_bytes(wxor, &pt[(m-1)*CRYPTO_BLOCKBYTES], PARTIAL_BLOCK_LEN(m, ctlen));
}

/**********************************************************************
 * 
 * @name	:	proc_tg
 * 
 * @note	:	Tag generator.
 * 
 **********************************************************************/
void proc_tg(u8 *tag, u8 *nonced_key, u8 *nonced_mask, u8 *vxor, u8 *wxor)
{
	u8 twk;
	
	// set control bits to 110
	twk = 0x06;
	
	// L_{a+m} = K_N \odot \alpha
	mult_by_alpha(nonced_key, nonced_key);
	
	// compute T = E^6_{L_{a+m}}(V_\xor + W_\xor + \Delta_N) + \Delta_N
	xor_bytes(vxor, wxor, CRYPTO_BLOCKBYTES);
	xor_bytes(vxor, nonced_mask, CRYPTO_BLOCKBYTES);
	twegift_enc(tag, nonced_key, &twk, vxor);
	xor_bytes(tag, nonced_mask, CRYPTO_BLOCKBYTES);
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
	// to bypass unused warning on nsec
	nsec = nsec;
	
	u8 nonced_key[CRYPTO_KEYBYTES];
	u8 nonced_mask[CRYPTO_NPUBBYTES];
	
	u8 tag[CRYPTO_ABYTES];
	
	u8 wxor[CRYPTO_BLOCKBYTES] = { 0 };
	u8 vxor[CRYPTO_BLOCKBYTES] = { 0 };
	
	// initialize and derive nonce-based key and mask
	u64 pt_blocks = ptlen%CRYPTO_BLOCKBYTES ? ((ptlen/CRYPTO_BLOCKBYTES)+1) : (ptlen/CRYPTO_BLOCKBYTES);
	u64 ad_blocks = adlen%CRYPTO_BLOCKBYTES ? ((adlen/CRYPTO_BLOCKBYTES)+1) : (adlen/CRYPTO_BLOCKBYTES);
	

	// CC - init -> Init
	Init(nonced_key, nonced_mask, k, npub);
	
	// process AD, if non-empty
	if(ad_blocks != 0)
	{
		proc_ad(nonced_key, vxor, nonced_mask, ad, ad_blocks, adlen);
	}
	
	// process PT, if non-empty
	if(pt_blocks != 0)
	{
		proc_pt(nonced_key, wxor, ct, ctlen, nonced_mask, pt, pt_blocks, ptlen);
	}
	else
	{
		*ctlen = 0;
	}
	
	// generate tag and append to ciphertext
	proc_tg(tag, nonced_key, nonced_mask, vxor, wxor);
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
	// to bypass unused warning on nsec
	nsec = nsec;
	
	ctlen = ctlen - CRYPTO_ABYTES;
	
	int pass;
	
	u8 nonced_key[CRYPTO_KEYBYTES];
	u8 nonced_mask[CRYPTO_NPUBBYTES];
	
	u8 tag[CRYPTO_ABYTES];
	
	u8 wxor[CRYPTO_BLOCKBYTES] = { 0 };
	u8 vxor[CRYPTO_BLOCKBYTES] = { 0 };
	
	// initialize and derive nonce-based key and mask
	u64 ct_blocks = ctlen%CRYPTO_BLOCKBYTES ? ((ctlen/CRYPTO_BLOCKBYTES)+1) : (ctlen/CRYPTO_BLOCKBYTES);
	u64 ad_blocks = adlen%CRYPTO_BLOCKBYTES ? ((adlen/CRYPTO_BLOCKBYTES)+1) : (adlen/CRYPTO_BLOCKBYTES);
	
	// CC - init -> Init
	Init(nonced_key, nonced_mask, k, npub);
	
	// process AD, if non-empty
	if(ad_blocks != 0)
	{
		proc_ad(nonced_key, vxor, nonced_mask, ad, ad_blocks, adlen);
	}
	
	// process CT, if non-empty
	if(ct_blocks != 0)
	{
		proc_ct(nonced_key, wxor, pt, ptlen, nonced_mask, ct, ct_blocks, ctlen);
	}
	else
	{
		*ptlen = 0;
	}
	
	// generate tag
	proc_tg(tag, nonced_key, nonced_mask, vxor, wxor);
	
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
