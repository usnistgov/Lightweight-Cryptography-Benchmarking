/*
 * An optimized version of Grain128-AEAD.
 *
 * This implementation utilizes the full level of
 * parallelization of Grain. It processes 32 bits at a time
 * for maximum throughput. Due to the endianess on most machines
 * being little endian, we interpret every byte with LSB first,
 * in order for the bit streams to be in the expected order
 * (but backwards).
 *
 * Jonathan Sönnerup
 * 2019
 */

#include <inttypes.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#include "grain128aead_32p.h"

static const uint32_t mvo0 = 0x22222222;
static const uint32_t mvo1 = 0x18181818;
static const uint32_t mvo2 = 0x07800780;
static const uint32_t mvo3 = 0x007f8000;
static const uint32_t mvo4 = 0x80000000;

static const uint32_t mve0 = 0x44444444;
static const uint32_t mve1 = 0x30303030;
static const uint32_t mve2 = 0x0f000f00;
static const uint32_t mve3 = 0x00ff0000;



u32 next_keystream(grain_ctx *grain)
{
	u64 ln0 = (((u64) *(grain->lptr + 1)) << 32) | *(grain->lptr),
	    ln1 = (((u64) *(grain->lptr + 2)) << 32) | *(grain->lptr + 1),
	    ln2 = (((u64) *(grain->lptr + 3)) << 32) | *(grain->lptr + 2),
	    ln3 = (((u64) *(grain->lptr + 3)));
	u64 nn0 = (((u64) *(grain->nptr + 1)) << 32) | *(grain->nptr),
	    nn1 = (((u64) *(grain->nptr + 2)) << 32) | *(grain->nptr + 1),
	    nn2 = (((u64) *(grain->nptr + 3)) << 32) | *(grain->nptr + 2),
	    nn3 = (((u64) *(grain->nptr + 3)));

	// f
	grain->lfsr[grain->count] = (ln0 ^ ln3) ^ ((ln1 ^ ln2) >> 6) ^ (ln0 >> 7) ^ (ln2 >> 17);

	// g                        s0    b0        b26       b96       b56             b91 + b27b59
	grain->nfsr[grain->count] = ln0 ^ nn0 ^ (nn0 >> 26) ^ nn3 ^ (nn1 >> 24) ^ (((nn0 & nn1) ^ nn2) >> 27) ^
				//     b3b67                   b11b13                        b17b18
				((nn0 & nn2) >> 3) ^ ((nn0 >> 11) & (nn0 >> 13)) ^ ((nn0 >> 17) & (nn0 >> 18)) ^
				//       b40b48                        b61b65                      b68b84
				((nn1 >> 8) & (nn1 >> 16)) ^ ((nn1 >> 29) & (nn2 >> 1)) ^ ((nn2 >> 4) & (nn2 >> 20)) ^
				//                   b88b92b93b95
				((nn2 >> 24) & (nn2 >> 28) & (nn2 >> 29) & (nn2 >> 31)) ^
				//              b22b24b25                                  b70b78b82
				((nn0 >> 22) & (nn0 >> 24) & (nn0 >> 25)) ^ ((nn2 >> 6) & (nn2 >> 14) & (nn2 >> 18));
	
	grain->count++;
	grain->lptr++;
	grain->nptr++;

	// move the state to the beginning of the buffers
	if (grain->count >= BUF_SIZE) grain_reinit(grain);

	return (nn0 >> 2) ^ (nn0 >> 15) ^ (nn1 >> 4) ^ (nn1 >> 13) ^ nn2 ^ (nn2 >> 9) ^ (nn2 >> 25) ^ (ln2 >> 29) ^
		((nn0 >> 12) & (ln0 >> 8)) ^ ((ln0 >> 13) & (ln0 >> 20)) ^ ((nn2 >> 31) & (ln1 >> 10)) ^
		((ln1 >> 28) & (ln2 >> 15)) ^ ((nn0 >> 12) & (nn2 >> 31) & (ln2 >> 30));
}

void auth_accumulate(grain_ctx *grain, u16 ms, u16 msg)
{
	/* updates the authentication module using the 
	 * MAC stream (ms) and the plaintext (msg)
	 */
	u16 mstmp = ms;
	u16 acctmp = 0;
	u32 regtmp = (u32) ms << 16;

	for (int i = 0; i < 16; i++) {
		u64 mask = 0x00;
		u32 mask_rem = 0x00;
		if (msg & 0x0001) {
			mask = ~mask; // all ones
			mask_rem = 0x0000ffff;
		}

		grain->acc ^= grain->reg & mask;
		grain->reg >>= 1;

		acctmp ^= regtmp & mask_rem;
		regtmp >>= 1;

		mstmp >>= 1;

		msg >>= 1;
	}

	grain->reg |= ((u64) ms << 48);
	grain->acc ^= ((u64) acctmp << 48);

}

void auth_accumulate8(grain_ctx *grain, u8 ms, u8 msg)
{
	/* updates the authentication module using the 
	 * MAC stream (ms) and the plaintext (msg)
	 */
	u8 mstmp = ms;
	u8 acctmp = 0;
	u16 regtmp = (u16) ms << 8;

	for (int i = 0; i < 8; i++) {
		u64 mask = 0x00;
		u32 mask_rem = 0x00;
		if (msg & 0x01) {
			mask = ~mask; // all ones
			mask_rem = 0x00ff;
		}

		grain->acc ^= grain->reg & mask;
		grain->reg >>= 1;

		acctmp ^= regtmp & mask_rem;
		regtmp >>= 1;

		mstmp >>= 1;

		msg >>= 1;
	}

	grain->reg |= ((u64) ms << 56);
	grain->acc ^= ((u64) acctmp << 56);

}

void grain_init(grain_ctx *grain, const u8 *key, const u8 *iv)
{
	// load key, and IV along with padding
	memcpy(grain->nfsr, key, 16);
	memcpy(grain->lfsr, iv, 12);
	*(u32 *) (grain->lfsr + 3) = (u32) 0x7fffffff; // 0xfffffffe in little endian, LSB first

	grain->count = 4;
	grain->nptr = grain->nfsr;
	grain->lptr = grain->lfsr;

	register u32 ks;
	for (int i = 0; i < 8; i++) {
		ks = next_keystream(grain);
		grain->nfsr[i + 4] ^= ks;
		grain->lfsr[i + 4] ^= ks;
	}

	// add the key in the feedback, "FP(1)" and initialize auth module
	grain->acc = 0;
	for (int i = 0; i < 2; i++) {
		// initialize accumulator
		ks = next_keystream(grain);
		grain->acc |= ((u64) ks << (32 * i));
		grain->lfsr[i + 12] ^= *(u32 *) (key + 4 * i);
	}

	grain->reg = 0;
	for (int i = 0; i < 2; i++) {
		// initialize register
		ks = next_keystream(grain);
		grain->reg |= ((u64) ks << (32 * i));
		grain->lfsr[i + 14] ^= *(u32 *) (key + 8 + 4 * i);
	}
}

void grain_reinit(grain_ctx *grain)
{
	*(u32 *) (grain->lfsr) = *(u32 *) (grain->lptr);
	*(u32 *) (grain->lfsr + 1) = *(u32 *) (grain->lptr + 1);
	*(u32 *) (grain->lfsr + 2) = *(u32 *) (grain->lptr + 2);
	*(u32 *) (grain->lfsr + 3) = *(u32 *) (grain->lptr + 3);

	*(u32 *) (grain->nfsr + 0) = *(u32 *) (grain->nptr + 0);
	*(u32 *) (grain->nfsr + 1) = *(u32 *) (grain->nptr + 1);
	*(u32 *) (grain->nfsr + 2) = *(u32 *) (grain->nptr + 2);
	*(u32 *) (grain->nfsr + 3) = *(u32 *) (grain->nptr + 3);

	grain->lptr = grain->lfsr;
	grain->nptr = grain->nfsr;
	grain->count = 4;
}

u16 getmb(u32 num)
{
	// compress x using the mask 0xAAAAAAAA to extract the (odd) MAC bits, LSB first
	register u32 t;
	register u32 x = num & 0xAAAAAAAA;
	t = x & mvo0; x = (x ^ t) | (t >> 1);
	t = x & mvo1; x = (x ^ t) | (t >> 2);
	t = x & mvo2; x = (x ^ t) | (t >> 4);
	t = x & mvo3; x = (x ^ t) | (t >> 8);
	t = x & mvo4; x = (x ^ t) | (t >> 16);

	return (u16) x;
}

u16 getkb(u32 num)
{
	// compress x using the mask 0x55555555 to extract the (even) key bits, LSB first
	register u32 t;
	register u32 x = num & 0x55555555;
	t = x & mve0; x = (x ^ t) | (t >> 1);
	t = x & mve1; x = (x ^ t) | (t >> 2);
	t = x & mve2; x = (x ^ t) | (t >> 4);
	t = x & mve3; x = (x ^ t) | (t >> 8);

	return (u16) x;
}

int encode_der(unsigned long long len, u8 **der)
{
	unsigned long long len_tmp;
	int der_len = 0;

	if (len < 128) {
		*der = malloc(1);
		(*der)[0] = len;
		return 1;
	}

	len_tmp = len;
	do {
		len_tmp >>= 8;
		der_len++;
	} while (len_tmp != 0);

	// one extra byte to describe the number of bytes used
	*der = malloc(der_len + 1);
	(*der)[0] = 0x80 | der_len;

	len_tmp = len;
	for (int i = der_len; i > 0; i--) {
		(*der)[i] = len_tmp & 0xff;	// mod 256
		len_tmp >>= 8;
	}

	return der_len + 1;
}


int crypto_aead_encrypt(
	unsigned char *c, unsigned long long *clen,
	const unsigned char *m, unsigned long long mlen,
	const unsigned char *ad, unsigned long long adlen,
	const unsigned char *nsec,
	const unsigned char *npub,
	const unsigned char *k)
{
	grain_ctx grain;
	grain_init(&grain, k, npub);

	*clen = 0;
	unsigned long long mmlen = mlen;

	// authenticate length of AD
	// encode length using DER
	u8 *ader;
	int aderlen = encode_der(adlen, &ader);
	ader = realloc(ader, aderlen + adlen);
	memcpy(ader + aderlen, ad, adlen);

	unsigned long long itr = (aderlen + adlen) / 2;
	unsigned long long rem = (aderlen + adlen) % 2;
	unsigned long long j = 0;
	u32 next;
	u32 rem_word;

	// authenticate AD
	for (unsigned long long i = 0; i < itr; i++) {
		next = next_keystream(&grain);
		auth_accumulate(&grain, getmb(next), *(u16 *) (ader + j));
		j += 2;;
	}

	if (rem) {
		rem_word = next_keystream(&grain);
		auth_accumulate8(&grain, getmb(rem_word), *(ader + j));
	}

	free(ader);

	j = 0;

	// use the last 8 bits in rem_word for the message
	if (rem && mlen) {
		*(c + j) = ((u8) (getkb(rem_word) >> 8)) ^ *(m + j);
		auth_accumulate8(&grain, getmb(rem_word) >> 8, *(m + j));
		*clen += 1;
		j++;
		mmlen--; // one byte processed
	}


	itr = mmlen / 2;
	rem = mmlen % 2;

	// encrypt and authenticate message
	for (unsigned long long i = 0; i < itr; i++) {
		next = next_keystream(&grain);
		//*(u16 *) (c + j) = getkb(next) ^ (*(u16 *) (m + j));
		u16 tmp;
		memcpy(&tmp, (m + j), 2);
		tmp = getkb(next) ^ tmp;
		memcpy((c + j), &tmp, 2);
		auth_accumulate(&grain, getmb(next), *(u16 *) (m + j));
		j += 2;
		*clen += 2;
	}

	rem_word = next_keystream(&grain);
	if (rem) {
		*(c + j) = ((u8) (getkb(rem_word))) ^ *(m + j);
		// add padding to the last byte of plaintext
		auth_accumulate(&grain, getmb(rem_word), 0x0100 | *(m + j));
		*clen += 1;
	} else {
		auth_accumulate(&grain, getmb(rem_word), 0x01);
	}
	
	// append MAC to ciphertext
	memcpy(c + mlen, &grain.acc, 8);

	*clen += 8;

	return 0;
}

int crypto_aead_decrypt(
	unsigned char *m, unsigned long long *mlen,
	unsigned char *nsec,
	const unsigned char *c, unsigned long long clen,
	const unsigned char *ad, unsigned long long adlen,
	const unsigned char *npub,
	const unsigned char *k
)
{
	grain_ctx grain;
	grain_init(&grain, k, npub);


	// length of ciphertext, no tag
	unsigned long long cclen = clen - 8;
	*mlen = 0;

	// authenticate length of AD
	// encode length using DER
	u8 *ader;
	int aderlen = encode_der(adlen, &ader);
	ader = realloc(ader, aderlen + adlen);
	memcpy(ader + aderlen, ad, adlen);

	unsigned long long itr = (aderlen + adlen) / 2;
	unsigned long long rem = (aderlen + adlen) % 2;
	unsigned long long j = 0;
	u32 next;
	u32 rem_word;

	// authenticate AD
	for (unsigned long long i = 0; i < itr; i++) {
		next = next_keystream(&grain);
		auth_accumulate(&grain, getmb(next), *(u16 *) (ader + j));
		j += 2;
	}

	if (rem) {
		rem_word = next_keystream(&grain);
		auth_accumulate8(&grain, getmb(rem_word), *(ader + j));
	}

	free(ader);

	j = 0;

	// use the last 8 bits in rem_word for the message
	if (rem && cclen) {
		*(m + j) = ((u8) (getkb(rem_word) >> 8)) ^ *(c + j);
		auth_accumulate8(&grain, getmb(rem_word) >> 8, *(m + j));
		j++;
		cclen--;
		*mlen += 1;
	}


	itr = cclen / 2;
	rem = cclen % 2;

	// encrypt and authenticate message
	for (unsigned long long i = 0; i < itr; i++) {
		next = next_keystream(&grain);
		//*(u16 *) (m + j) = getkb(next) ^ (*(u16 *) (c + j));
		u16 tmp;
		memcpy(&tmp, (c + j), 2);
		tmp = getkb(next) ^ tmp;
		memcpy((m + j), &tmp, 2);
		auth_accumulate(&grain, getmb(next), *(u16 *) (m + j));
		j += 2;
		*mlen += 2;
	}

	rem_word = next_keystream(&grain);
	if (rem) {
		*(m + j) = ((u8) (getkb(rem_word))) ^ *(c + j);
		// add padding to the last byte of plaintext
		auth_accumulate(&grain, getmb(rem_word), 0x0100 | *(m + j));
		*mlen += 1;
	} else {
		auth_accumulate(&grain, getmb(rem_word), 0x01);
	}

	if (memcmp(&grain.acc, (c + (clen-8)), 8) != 0) {
		memset(m, 0, *mlen);
		return -1;
	}

	return 0;
}
