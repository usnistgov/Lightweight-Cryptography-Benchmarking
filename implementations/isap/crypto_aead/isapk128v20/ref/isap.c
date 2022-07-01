#include <stdio.h>
#include <string.h>
#include "api.h"
#include "isap.h"
#include "KeccakP-400-SnP.h"

const unsigned char ISAP_IV_A[] = {0x01,ISAP_K,ISAP_rH,ISAP_rB,ISAP_sH,ISAP_sB,ISAP_sE,ISAP_sK};
const unsigned char ISAP_IV_KA[] = {0x02,ISAP_K,ISAP_rH,ISAP_rB,ISAP_sH,ISAP_sB,ISAP_sE,ISAP_sK};
const unsigned char ISAP_IV_KE[] = {0x03,ISAP_K,ISAP_rH,ISAP_rB,ISAP_sH,ISAP_sB,ISAP_sE,ISAP_sK};

/******************************************************************************/
/*                                   IsapRk                                   */
/******************************************************************************/

void isap_rk(
	const unsigned char *k,
	const unsigned char *iv,
	const unsigned char *in,
	const unsigned long long inlen,
	unsigned char *out,
	const unsigned long long outlen
){
	// Init State
	unsigned char state[ISAP_STATE_SZ];
	KeccakP400_Initialize(state);
	KeccakP400_AddBytes(state,k,0,CRYPTO_KEYBYTES);
	KeccakP400_AddBytes(state,iv,CRYPTO_KEYBYTES,ISAP_IV_SZ);
	KeccakP400_Permute_Nrounds(state,ISAP_sK);

	// Absorb
	for (size_t i = 0; i < inlen*8-1; i++){
		size_t cur_byte_pos = i/8;
		size_t cur_bit_pos = 7-(i%8);
		unsigned char cur_bit = ((in[cur_byte_pos] >> (cur_bit_pos)) & 0x01) << 7;
		KeccakP400_AddBytes(state,(const unsigned char*)&cur_bit,0,1);
		KeccakP400_Permute_Nrounds(state,ISAP_sB);
	}
	unsigned char cur_bit = ((in[inlen-1]) & 0x01) << 7;
	KeccakP400_AddBytes(state,(const unsigned char*)&cur_bit,0,1);
	KeccakP400_Permute_Nrounds(state,ISAP_sK);

	// Squeeze K*
	KeccakP400_ExtractBytes(state,out,0,outlen);
}

/****************************************/
/*               IsapMac                */
/****************************************/

void isap_mac(
	const unsigned char *k,
	const unsigned char *npub,
	const unsigned char *ad, const unsigned long long adlen,
	const unsigned char *c, const unsigned long long clen,
	unsigned char *tag
){
	// Init State
	unsigned char state[ISAP_STATE_SZ];
	KeccakP400_Initialize(state);
	KeccakP400_AddBytes(state,npub,0,CRYPTO_NPUBBYTES);
	KeccakP400_AddBytes(state,ISAP_IV_A,CRYPTO_NPUBBYTES,ISAP_IV_SZ);
	KeccakP400_Permute_Nrounds(state,ISAP_sH);

	// Absorb AD
	size_t rate_bytes_avail = ISAP_rH_SZ;
	unsigned char cur_ad;
	for (unsigned long long i = 0; i < adlen; i++){
		if(rate_bytes_avail == 0){
			KeccakP400_Permute_Nrounds(state,ISAP_sH);
			rate_bytes_avail = ISAP_rH_SZ;
		}
		cur_ad = ad[i];
		KeccakP400_AddBytes(state,&cur_ad,ISAP_rH_SZ-rate_bytes_avail,1);
		rate_bytes_avail--;
	}

	// Absorb Padding: 0x80
	if(rate_bytes_avail == 0){
		KeccakP400_Permute_Nrounds(state,ISAP_sH);
		rate_bytes_avail = ISAP_rH_SZ;
	}
	unsigned char pad = 0x80;
	KeccakP400_AddBytes(state,&pad,ISAP_rH_SZ-rate_bytes_avail,1);
	KeccakP400_Permute_Nrounds(state,ISAP_sH);

	// Domain Seperation: 0x01
	unsigned char dom_sep = 0x01;
	KeccakP400_AddBytes(state,&dom_sep,ISAP_STATE_SZ-1,1);

	// Absorb C
	rate_bytes_avail = ISAP_rH_SZ;
	unsigned char cur_c;
	for (unsigned long long i = 0; i < clen; i++){
		cur_c = c[i];
		KeccakP400_AddBytes(state,&cur_c,ISAP_rH_SZ-rate_bytes_avail,1);
		rate_bytes_avail--;
		if(rate_bytes_avail == 0){
			KeccakP400_Permute_Nrounds(state,ISAP_sH);
			rate_bytes_avail = ISAP_rH_SZ;
		}
	}

	// Absorb Padding: 0x80
	pad = 0x80;
	KeccakP400_AddBytes(state,&pad,ISAP_rH_SZ-rate_bytes_avail,1);
	KeccakP400_Permute_Nrounds(state,ISAP_sH);

	// Derive Ka*
	unsigned char y[CRYPTO_KEYBYTES];
	unsigned char ka_star[CRYPTO_KEYBYTES];
	KeccakP400_ExtractBytes(state,y,0,CRYPTO_KEYBYTES);
	isap_rk(k,ISAP_IV_KA,y,CRYPTO_KEYBYTES,ka_star,CRYPTO_KEYBYTES);

	// Squeezing Tag
	KeccakP400_OverwriteBytes(state,ka_star,0,CRYPTO_KEYBYTES);
	KeccakP400_Permute_Nrounds(state,ISAP_sH);
	KeccakP400_ExtractBytes(state,tag,0,CRYPTO_KEYBYTES);
}

/****************************************/
/*               IsapEnc                */
/****************************************/

void isap_enc(
	const unsigned char *k,
	const unsigned char *npub,
	const unsigned char *m, const unsigned long long mlen,
	unsigned char *c
){
	// Derive Ke*
	unsigned char state[ISAP_STATE_SZ];
	isap_rk(k,ISAP_IV_KE,npub,CRYPTO_NPUBBYTES,state,ISAP_STATE_SZ-CRYPTO_NPUBBYTES);
	KeccakP400_OverwriteBytes(state,npub,ISAP_STATE_SZ-CRYPTO_NPUBBYTES,CRYPTO_NPUBBYTES);

	// Squeeze Keystream
	size_t key_bytes_avail = 0;
	for (unsigned long long i = 0; i < mlen; i++) {
		if(key_bytes_avail == 0){
			KeccakP400_Permute_Nrounds(state,ISAP_sE);
			key_bytes_avail = ISAP_rH_SZ;
		}
		unsigned char keybyte;
		KeccakP400_ExtractBytes(state,&keybyte,i%ISAP_rH_SZ,1);
		c[i] = m[i] ^ keybyte;
		key_bytes_avail--;
	}
}
