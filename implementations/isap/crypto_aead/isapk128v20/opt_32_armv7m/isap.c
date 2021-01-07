#include "api.h"
#include "isap.h"
#include "inttypes.h"
#include "KeccakP-400-SnP.h"

const unsigned char ISAP_IV1[] = {0x01,ISAP_K,ISAP_rH,ISAP_rB,ISAP_sH,ISAP_sB,ISAP_sE,ISAP_sK};
const unsigned char ISAP_IV2[] = {0x02,ISAP_K,ISAP_rH,ISAP_rB,ISAP_sH,ISAP_sB,ISAP_sE,ISAP_sK};
const unsigned char ISAP_IV3[] = {0x03,ISAP_K,ISAP_rH,ISAP_rB,ISAP_sH,ISAP_sB,ISAP_sE,ISAP_sK};

/****************************************/
/*               IsapRk                 */
/****************************************/

void isap_rk(
	const unsigned char *k,
	const unsigned char *iv,
	const unsigned char *in,
	const unsigned long inlen,
	unsigned char *out,
	const unsigned long outlen
){
	// Init State
	unsigned char state[ISAP_STATE_SZ] __attribute__((aligned(4)));
	KeccakP400_Initialize(state);
	KeccakP400_AddBytes(state,k,0,CRYPTO_KEYBYTES);
	KeccakP400_AddBytes(state,iv,CRYPTO_KEYBYTES,ISAP_IV_SZ);
	KeccakP400_Permute_Nrounds(state,ISAP_sK);

	// Absorb
	for (unsigned long i = 0; i < inlen*8-1; i++){
		unsigned long cur_byte_pos = i/8;
		unsigned long cur_bit_pos = 7-(i%8);
		unsigned char cur_bit = ((in[cur_byte_pos] >> (cur_bit_pos)) & 0x01) << 7;
		state[0] ^= cur_bit;
		KeccakP400_Permute_Nrounds(state,ISAP_sB);
	}
	unsigned char cur_bit = ((in[inlen-1]) & 0x01) << 7;
	state[0] ^= cur_bit;
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
	const unsigned char *ad, const unsigned long adlen,
	const unsigned char *c, const unsigned long clen,
	unsigned char *tag
){
	// Init State
	unsigned char state[ISAP_STATE_SZ] __attribute__ ((aligned(4)));
	uint16_t *state16 = (uint16_t *)state;
	uint16_t *ad16 = (uint16_t *)ad;
	uint16_t *c16 = (uint16_t *)c;

	KeccakP400_Initialize(state);
	KeccakP400_AddBytes(state,npub,0,CRYPTO_NPUBBYTES);
	KeccakP400_AddBytes(state,ISAP_IV1,CRYPTO_NPUBBYTES,ISAP_IV_SZ);
	KeccakP400_Permute_Nrounds(state,ISAP_sH);

	// Absorb AD
	unsigned long idx16 = 0;
	unsigned long rem_bytes = adlen;
	while(rem_bytes>=18){
			state16[0] ^= ad16[idx16+0];
			state16[1] ^= ad16[idx16+1];
			state16[2] ^= ad16[idx16+2];
			state16[3] ^= ad16[idx16+3];
			state16[4] ^= ad16[idx16+4];
			state16[5] ^= ad16[idx16+5];
			state16[6] ^= ad16[idx16+6];
			state16[7] ^= ad16[idx16+7];
			state16[8] ^= ad16[idx16+8];
			rem_bytes -= 18;
			idx16 += 9;
			KeccakP400_Permute_Nrounds(state,ISAP_sH);
	}
	uint32_t idx8 = idx16*2;
	for (uint32_t i = 0; i < rem_bytes; i++) {
			state[i] ^= ad[idx8+i];
	}
	state[rem_bytes] ^= 0x80;
	KeccakP400_Permute_Nrounds(state,ISAP_sH);

	// Domain Seperation
	state[ISAP_STATE_SZ-1] ^= 0x01;

	// Absorb C
	idx16 = 0;
	rem_bytes = clen;
	while(rem_bytes>=18){
			state16[0] ^= c16[idx16+0];
			state16[1] ^= c16[idx16+1];
			state16[2] ^= c16[idx16+2];
			state16[3] ^= c16[idx16+3];
			state16[4] ^= c16[idx16+4];
			state16[5] ^= c16[idx16+5];
			state16[6] ^= c16[idx16+6];
			state16[7] ^= c16[idx16+7];
			state16[8] ^= c16[idx16+8];
			rem_bytes -= 18;
			idx16 += 9;
			KeccakP400_Permute_Nrounds(state,ISAP_sH);
	}
	idx8 = idx16*2;
	for (uint32_t i = 0; i < rem_bytes; i++) {
			state[i] ^= c[idx8+i];
	}
	state[rem_bytes] ^= 0x80;
	KeccakP400_Permute_Nrounds(state,ISAP_sH);

	// Derive Ka*
	unsigned char y[CRYPTO_KEYBYTES];
	unsigned char ka_star[CRYPTO_KEYBYTES];
	KeccakP400_ExtractBytes(state,y,0,CRYPTO_KEYBYTES);
	isap_rk(k,ISAP_IV2,y,CRYPTO_KEYBYTES,ka_star,CRYPTO_KEYBYTES);

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
	const unsigned char *m, const unsigned long mlen,
	unsigned char *c
){
	uint8_t state[ISAP_STATE_SZ] __attribute__((aligned(4)));
	uint16_t *state16 = (uint16_t *)state;
	uint16_t *c16 = (uint16_t *)c;
	uint16_t *m16 = (uint16_t *)m;

	isap_rk(k,ISAP_IV3,npub,CRYPTO_NPUBBYTES,(unsigned char *)state,ISAP_STATE_SZ-CRYPTO_NPUBBYTES);
	KeccakP400_OverwriteBytes(state,npub,ISAP_STATE_SZ-CRYPTO_NPUBBYTES,CRYPTO_NPUBBYTES);

	uint16_t ks16[9];
	unsigned long idx16 = 0;
	unsigned long rem_bytes = mlen;

	// Squeeze Keystream
	while(rem_bytes>=18){
			KeccakP400_Permute_Nrounds(state,ISAP_sE);
			c16[idx16+0] = m16[idx16+0] ^ state16[0];
			c16[idx16+1] = m16[idx16+1] ^ state16[1];
			c16[idx16+2] = m16[idx16+2] ^ state16[2];
			c16[idx16+3] = m16[idx16+3] ^ state16[3];
			c16[idx16+4] = m16[idx16+4] ^ state16[4];
			c16[idx16+5] = m16[idx16+5] ^ state16[5];
			c16[idx16+6] = m16[idx16+6] ^ state16[6];
			c16[idx16+7] = m16[idx16+7] ^ state16[7];
			c16[idx16+8] = m16[idx16+8] ^ state16[8];
			rem_bytes -= 18;
			idx16 += 9;
	}

	// Squeeze Keystream
	if(rem_bytes>0){
			KeccakP400_Permute_Nrounds(state,ISAP_sE);
			unsigned long idx8 = idx16*2;
			for (uint32_t i = 0; i < rem_bytes; i++) {
				c[idx8+i] = m[idx8+i] ^ state[i];
			}
	}
}
