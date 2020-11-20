/* ======================================================================== */
/*
 * Saturnin-CTR-Cascade (NIST API).
 *
 * bs32x: this implementation expands each Saturnin 16-bit register into
 * the even bits of a 32-bit register. The odd bits can be used to run
 * another instance in parallel.
 */

#include "crypto_aead.h"

#include <string.h>
#include <stdint.h>

/*
 * We represent the sixteen 16-bit registers r0..r15 into sixteen 32-bit
 * variables h0, h1,... hF, using the even bits (bit i of rj becomes
 * bit 2*i of hj). The odd bits optionally receive another instance.
 */

#define DECL_STATE_X2   \
	uint32_t h0, h1, h2, h3, h4, h5, h6, h7; \
	uint32_t h8, h9, hA, hB, hC, hD, hE, hF;

#define EXPAND(x)   do { \
		uint32_t xp = (x); \
		xp = (xp & 0x000000FF) | ((xp & 0x0000FF00) << 8); \
		xp = (xp & 0x000F000F) | ((xp & 0x00F000F0) << 4); \
		xp = (xp & 0x03030303) | ((xp & 0x0C0C0C0C) << 2); \
		xp = (xp & 0x11111111) | ((xp & 0x22222222) << 1); \
		(x) = xp; \
	} while (0)

#define DEC256_INNER(d, src)   do { \
		d ## 0 = (uint32_t)(src)[ 0] | ((uint32_t)(src)[ 1] << 8); \
		d ## 1 = (uint32_t)(src)[ 2] | ((uint32_t)(src)[ 3] << 8); \
		d ## 2 = (uint32_t)(src)[ 4] | ((uint32_t)(src)[ 5] << 8); \
		d ## 3 = (uint32_t)(src)[ 6] | ((uint32_t)(src)[ 7] << 8); \
		d ## 4 = (uint32_t)(src)[ 8] | ((uint32_t)(src)[ 9] << 8); \
		d ## 5 = (uint32_t)(src)[10] | ((uint32_t)(src)[11] << 8); \
		d ## 6 = (uint32_t)(src)[12] | ((uint32_t)(src)[13] << 8); \
		d ## 7 = (uint32_t)(src)[14] | ((uint32_t)(src)[15] << 8); \
		d ## 8 = (uint32_t)(src)[16] | ((uint32_t)(src)[17] << 8); \
		d ## 9 = (uint32_t)(src)[18] | ((uint32_t)(src)[19] << 8); \
		d ## A = (uint32_t)(src)[20] | ((uint32_t)(src)[21] << 8); \
		d ## B = (uint32_t)(src)[22] | ((uint32_t)(src)[23] << 8); \
		d ## C = (uint32_t)(src)[24] | ((uint32_t)(src)[25] << 8); \
		d ## D = (uint32_t)(src)[26] | ((uint32_t)(src)[27] << 8); \
		d ## E = (uint32_t)(src)[28] | ((uint32_t)(src)[29] << 8); \
		d ## F = (uint32_t)(src)[30] | ((uint32_t)(src)[31] << 8); \
		EXPAND(d ## 0); \
		EXPAND(d ## 1); \
		EXPAND(d ## 2); \
		EXPAND(d ## 3); \
		EXPAND(d ## 4); \
		EXPAND(d ## 5); \
		EXPAND(d ## 6); \
		EXPAND(d ## 7); \
		EXPAND(d ## 8); \
		EXPAND(d ## 9); \
		EXPAND(d ## A); \
		EXPAND(d ## B); \
		EXPAND(d ## C); \
		EXPAND(d ## D); \
		EXPAND(d ## E); \
		EXPAND(d ## F); \
	} while (0)

#define DEC256(src)  do { \
		DEC256_INNER(h, src); \
	} while (0)

#define DEC512(src)  do { \
		uint32_t m0, m1, m2, m3, m4, m5, m6, m7; \
		uint32_t m8, m9, mA, mB, mC, mD, mE, mF; \
		DEC256_INNER(h, src); \
		DEC256_INNER(m, (src) + 32); \
		h0 |= m0 << 1; \
		h1 |= m1 << 1; \
		h2 |= m2 << 1; \
		h3 |= m3 << 1; \
		h4 |= m4 << 1; \
		h5 |= m5 << 1; \
		h6 |= m6 << 1; \
		h7 |= m7 << 1; \
		h8 |= m8 << 1; \
		h9 |= m9 << 1; \
		hA |= mA << 1; \
		hB |= mB << 1; \
		hC |= mC << 1; \
		hD |= mD << 1; \
		hE |= mE << 1; \
		hF |= mF << 1; \
	} while (0)

#define ENC16(x, dst)   do { \
		uint32_t xp = (x); \
		xp = (xp & 0x11111111) | ((xp & 0x44444444) >> 1); \
		xp = (xp & 0x03030303) | ((xp & 0x30303030) >> 2); \
		xp = (xp & 0x000F000F) | ((xp & 0x0F000F00) >> 4); \
		(dst)[ 0] = (uint8_t)xp; \
		(dst)[ 1] = (uint8_t)(xp >> 16); \
	} while (0)

#define ENC256(dst)   do { \
		ENC16(h0, (dst) +  0); \
		ENC16(h1, (dst) +  2); \
		ENC16(h2, (dst) +  4); \
		ENC16(h3, (dst) +  6); \
		ENC16(h4, (dst) +  8); \
		ENC16(h5, (dst) + 10); \
		ENC16(h6, (dst) + 12); \
		ENC16(h7, (dst) + 14); \
		ENC16(h8, (dst) + 16); \
		ENC16(h9, (dst) + 18); \
		ENC16(hA, (dst) + 20); \
		ENC16(hB, (dst) + 22); \
		ENC16(hC, (dst) + 24); \
		ENC16(hD, (dst) + 26); \
		ENC16(hE, (dst) + 28); \
		ENC16(hF, (dst) + 30); \
	} while (0)

#define ENC512(dst)   do { \
		ENC256(dst); \
		h0 >>= 1; \
		h1 >>= 1; \
		h2 >>= 1; \
		h3 >>= 1; \
		h4 >>= 1; \
		h5 >>= 1; \
		h6 >>= 1; \
		h7 >>= 1; \
		h8 >>= 1; \
		h9 >>= 1; \
		hA >>= 1; \
		hB >>= 1; \
		hC >>= 1; \
		hD >>= 1; \
		hE >>= 1; \
		hF >>= 1; \
		ENC256((dst) + 32); \
	} while (0)

#define SBOX_0_X2(z0, z1, z2, z3)   do { \
		uint32_t a, b, c, d; \
		a = z0; \
		b = z1; \
		c = z2; \
		d = z3; \
		a ^= b & c; \
		b ^= a | d; \
		d ^= b | c; \
		c ^= b & d; \
		b ^= a | c; \
		a ^= b | d; \
		z0 = b; \
		z1 = c; \
		z2 = d; \
		z3 = a; \
	} while (0)

#define SBOX_1_X2(z0, z1, z2, z3)   do { \
		uint32_t a, b, c, d; \
		a = z0; \
		b = z1; \
		c = z2; \
		d = z3; \
		a ^= b & c; \
		b ^= a | d; \
		d ^= b | c; \
		c ^= b & d; \
		b ^= a | c; \
		a ^= b | d; \
		z0 = d; \
		z1 = b; \
		z2 = a; \
		z3 = c; \
	} while (0)

#define SBOX_X2   do { \
		SBOX_0_X2(h0, h1, h2, h3); \
		SBOX_1_X2(h4, h5, h6, h7); \
		SBOX_0_X2(h8, h9, hA, hB); \
		SBOX_1_X2(hC, hD, hE, hF); \
	} while (0)

#define MDS_X2   do { \
		/* q0 ^= q4; q1 ^= q5; q2 ^= q6; q3 ^= q7; */ \
		h0 ^= h4; \
		h1 ^= h5; \
		h2 ^= h6; \
		h3 ^= h7; \
		h8 ^= hC; \
		h9 ^= hD; \
		hA ^= hE; \
		hB ^= hF; \
		/* MUL(q4, q5, q6, q7); */ \
		h4 ^= h5; \
		hC ^= hD; \
		/* q4 ^= SW(q0); q5 ^= SW(q1); q6 ^= SW(q2); q7 ^= SW(q3); */ \
		h5 ^= h8; \
		h6 ^= h9; \
		h7 ^= hA; \
		h4 ^= hB; \
		hD ^= h0; \
		hE ^= h1; \
		hF ^= h2; \
		hC ^= h3; \
		/* MUL(q0, q1, q2, q3); */ \
		h0 ^= h1; \
		h8 ^= h9; \
		/* MUL(q0, q1, q2, q3); */ \
		h1 ^= h2; \
		h9 ^= hA; \
		/* q0 ^= q4; q1 ^= q5; q2 ^= q6; q3 ^= q7; */ \
		h2 ^= h5; \
		h3 ^= h6; \
		h0 ^= h7; \
		h1 ^= h4; \
		hA ^= hD; \
		hB ^= hE; \
		h8 ^= hF; \
		h9 ^= hC; \
		/* q4 ^= SW(q0); q5 ^= SW(q1); q6 ^= SW(q2); q7 ^= SW(q3); */ \
		h5 ^= hA; \
		h6 ^= hB; \
		h7 ^= h8; \
		h4 ^= h9; \
		hD ^= h2; \
		hE ^= h3; \
		hF ^= h0; \
		hC ^= h1; \
		/* Some register movement to avoid renaming (this should \
		   be optimized out by the compiler). */ \
		uint32_t tt; \
		tt = h0; h0 = h2; h2 = tt; \
		tt = h1; h1 = h3; h3 = tt; \
		tt = h4; h4 = h5; h5 = h6; h6 = h7; h7 = tt; \
		tt = h8; h8 = hA; hA = tt; \
		tt = h9; h9 = hB; hB = tt; \
		tt = hC; hC = hD; hD = hE; hE = hF; hF = tt; \
	} while (0)

#define SR_SLICE_X2   do { \
		h4 = ((h4 & 0x3F3F3F3F) << 2) | ((h4 & 0xC0C0C0C0) >> 6); \
		h5 = ((h5 & 0x3F3F3F3F) << 2) | ((h5 & 0xC0C0C0C0) >> 6); \
		h6 = ((h6 & 0x3F3F3F3F) << 2) | ((h6 & 0xC0C0C0C0) >> 6); \
		h7 = ((h7 & 0x3F3F3F3F) << 2) | ((h7 & 0xC0C0C0C0) >> 6); \
		h8 = ((h8 & 0x0F0F0F0F) << 4) | ((h8 & 0xF0F0F0F0) >> 4); \
		h9 = ((h9 & 0x0F0F0F0F) << 4) | ((h9 & 0xF0F0F0F0) >> 4); \
		hA = ((hA & 0x0F0F0F0F) << 4) | ((hA & 0xF0F0F0F0) >> 4); \
		hB = ((hB & 0x0F0F0F0F) << 4) | ((hB & 0xF0F0F0F0) >> 4); \
		hC = ((hC & 0x03030303) << 6) | ((hC & 0xFCFCFCFC) >> 2); \
		hD = ((hD & 0x03030303) << 6) | ((hD & 0xFCFCFCFC) >> 2); \
		hE = ((hE & 0x03030303) << 6) | ((hE & 0xFCFCFCFC) >> 2); \
		hF = ((hF & 0x03030303) << 6) | ((hF & 0xFCFCFCFC) >> 2); \
	} while (0)

#define SR_SLICE_X2_INV   do { \
		h4 = ((h4 & 0x03030303) << 6) | ((h4 & 0xFCFCFCFC) >> 2); \
		h5 = ((h5 & 0x03030303) << 6) | ((h5 & 0xFCFCFCFC) >> 2); \
		h6 = ((h6 & 0x03030303) << 6) | ((h6 & 0xFCFCFCFC) >> 2); \
		h7 = ((h7 & 0x03030303) << 6) | ((h7 & 0xFCFCFCFC) >> 2); \
		h8 = ((h8 & 0x0F0F0F0F) << 4) | ((h8 & 0xF0F0F0F0) >> 4); \
		h9 = ((h9 & 0x0F0F0F0F) << 4) | ((h9 & 0xF0F0F0F0) >> 4); \
		hA = ((hA & 0x0F0F0F0F) << 4) | ((hA & 0xF0F0F0F0) >> 4); \
		hB = ((hB & 0x0F0F0F0F) << 4) | ((hB & 0xF0F0F0F0) >> 4); \
		hC = ((hC & 0x3F3F3F3F) << 2) | ((hC & 0xC0C0C0C0) >> 6); \
		hD = ((hD & 0x3F3F3F3F) << 2) | ((hD & 0xC0C0C0C0) >> 6); \
		hE = ((hE & 0x3F3F3F3F) << 2) | ((hE & 0xC0C0C0C0) >> 6); \
		hF = ((hF & 0x3F3F3F3F) << 2) | ((hF & 0xC0C0C0C0) >> 6); \
	} while (0)

#define SR_SHEET_X2   do { \
		h4 = (h4 << 8) | (h4 >> 24); \
		h5 = (h5 << 8) | (h5 >> 24); \
		h6 = (h6 << 8) | (h6 >> 24); \
		h7 = (h7 << 8) | (h7 >> 24); \
		h8 = (h8 << 16) | (h8 >> 16); \
		h9 = (h9 << 16) | (h9 >> 16); \
		hA = (hA << 16) | (hA >> 16); \
		hB = (hB << 16) | (hB >> 16); \
		hC = (hC << 24) | (hC >> 8); \
		hD = (hD << 24) | (hD >> 8); \
		hE = (hE << 24) | (hE >> 8); \
		hF = (hF << 24) | (hF >> 8); \
	} while (0)

#define SR_SHEET_X2_INV   do { \
		h4 = (h4 << 24) | (h4 >> 8); \
		h5 = (h5 << 24) | (h5 >> 8); \
		h6 = (h6 << 24) | (h6 >> 8); \
		h7 = (h7 << 24) | (h7 >> 8); \
		h8 = (h8 << 16) | (h8 >> 16); \
		h9 = (h9 << 16) | (h9 >> 16); \
		hA = (hA << 16) | (hA >> 16); \
		hB = (hB << 16) | (hB >> 16); \
		hC = (hC << 8) | (hC >> 24); \
		hD = (hD << 8) | (hD >> 24); \
		hE = (hE << 8) | (hE >> 24); \
		hF = (hF << 8) | (hF >> 24); \
	} while (0)

#define XOR_KEY_X2   do { \
		h0 ^= keybuf[0x00]; \
		h1 ^= keybuf[0x01]; \
		h2 ^= keybuf[0x02]; \
		h3 ^= keybuf[0x03]; \
		h4 ^= keybuf[0x04]; \
		h5 ^= keybuf[0x05]; \
		h6 ^= keybuf[0x06]; \
		h7 ^= keybuf[0x07]; \
		h8 ^= keybuf[0x08]; \
		h9 ^= keybuf[0x09]; \
		hA ^= keybuf[0x0A]; \
		hB ^= keybuf[0x0B]; \
		hC ^= keybuf[0x0C]; \
		hD ^= keybuf[0x0D]; \
		hE ^= keybuf[0x0E]; \
		hF ^= keybuf[0x0F]; \
	} while (0)

#define XOR_KEY_ROTATED_X2   do { \
		h0 ^= keybuf[0x10]; \
		h1 ^= keybuf[0x11]; \
		h2 ^= keybuf[0x12]; \
		h3 ^= keybuf[0x13]; \
		h4 ^= keybuf[0x14]; \
		h5 ^= keybuf[0x15]; \
		h6 ^= keybuf[0x16]; \
		h7 ^= keybuf[0x17]; \
		h8 ^= keybuf[0x18]; \
		h9 ^= keybuf[0x19]; \
		hA ^= keybuf[0x1A]; \
		hB ^= keybuf[0x1B]; \
		hC ^= keybuf[0x1C]; \
		hD ^= keybuf[0x1D]; \
		hE ^= keybuf[0x1E]; \
		hF ^= keybuf[0x1F]; \
	} while (0)

/*
 * For Saturnin-CTR-Cascade: R = 10; D = 1, 2, 3, 4 or 5.
 */

static const uint32_t RC_10_2_X2[] = {
	0x0C3CCF33, 0x30FC3033, 0x33FFFF00, 0xCC0F333C,
	0x0C00F3C0, 0x00FFC0FF, 0xCFFCFC03, 0x00CF3330,
	0x3CF0C3F3, 0x3FF303CC, 0x0CC000CC, 0x033FCC3C,
	0xF0C3C03C, 0xCCCC303C, 0xC3003C0C, 0xF00303C3,
	0x33F0F3FC, 0x03C00CF0, 0x330FFFFC, 0xCC0000F3
};

static const uint32_t RC_10_3_X2[] = {
	0x0C3CC3C0, 0x30FC033C, 0x33CFCC03, 0xCF0C330F,
	0xC3F33C33, 0x3CF0C0FF, 0xCCF30F00, 0x33C0033C,
	0xF330FFCC, 0x3CC303FF, 0xCFF0FFC3, 0x3CCFFF33,
	0x0F330C33, 0xFFC0FCCF, 0xFCF0FFCC, 0xCF0C03F3,
	0xCC30033F, 0x3FCF0FF3, 0xC330CF30, 0xFF3C0CF0
};

static const uint32_t RC_10_combined_1_4_X2[] = {
	0x0C3C728E, 0x30FECDAA, 0x312D022D, 0xE12231C1,
	0xDCB60D06, 0x6466E2F5, 0xE26C412E, 0xFD54C18E,
	0xEEB28BC1, 0x10230131, 0x6319272E, 0x43AD13AF,
	0xF058127C, 0x3173EF8B, 0x839B52EE, 0xB99A2319,
	0x31B94E48, 0x675903D7, 0xA14402D1, 0x336496D4
};

static const uint32_t RC_10_combined_1_5_X2[] = {
	0x0C3C7A2C, 0x30FEEFA0, 0x310D202F, 0xE32031E3,
	0x561487A4, 0x4C6CE2F5, 0xE066E32C, 0xDF5EE186,
	0x6432A3EB, 0x12030113, 0xE1398D24, 0x690D31A5,
	0x5AF89A76, 0x137B6729, 0xA93BD06E, 0x93902339,
	0x9B39EECA, 0x4F5301D5, 0x016E2259, 0x114C9ED6
};

/*
 * Decode a key into 32-bit words (with bs32x encoding, and
 * followed by the rotated key); only the "even" keys are set (the odd bits
 * are set to zero).
 */
static void
saturnin_x2_key_expand_even(uint32_t *keybuf, const uint8_t *key)
{
	int i;

	for (i = 0; i < 16; i ++) {
		uint32_t w;

		w = (uint32_t)key[i << 1] | ((uint32_t)key[(i << 1) + 1] << 8);
		EXPAND(w);
		keybuf[i] = w;
		keybuf[i + 16] = (w << 22) | (w >> 10);
	}
}

/*
 * Perform two parallel Saturnin block encryptions.
 *   R        number of super-rounds
 *   rc       round constants (depends on R and D)
 *   keybuf   key and rotated key (16 words = 64 bytes)
 *   buf      blocks to encrypt
 * The encrypted block is written back in 'buf'.
 */
static void
saturnin_x2_block_encrypt(int R, const uint32_t *rc,
	const uint32_t *keybuf, uint8_t *buf)
{
	DECL_STATE_X2
	int i;

	/*
	 * Decode data into the registers.
	 */
	DEC512(buf);

	XOR_KEY_X2;

	/*
	 * Run all rounds (two rounds per super-round, two super-rounds
	 * per loop iteration).
	 */
	for (i = 0; i < R; i += 2) {
		/*
		 * Even round.
		 */
		SBOX_X2;
		MDS_X2;

		/*
		 * Odd round r = 1 mod 4.
		 */
		SBOX_X2;
		SR_SLICE_X2;
		MDS_X2;
		SR_SLICE_X2_INV;
		h0 ^= rc[(i << 1) + 0];
		h8 ^= rc[(i << 1) + 1];
		XOR_KEY_ROTATED_X2;

		/*
		 * Even round.
		 */
		SBOX_X2;
		MDS_X2;

		/*
		 * Odd round r = 3 mod 4.
		 */
		SBOX_X2;
		SR_SHEET_X2;
		MDS_X2;
		SR_SHEET_X2_INV;
		h0 ^= rc[(i << 1) + 2];
		h8 ^= rc[(i << 1) + 3];
		XOR_KEY_X2;
	}

	/*
	 * Encode back the result.
	 */
	ENC512(buf);
}

/*
 * XOR 256-bit value a into 256-bit value d. The two arrays shall not
 * overlap.
 */
static inline void
xor32(uint8_t *d, const uint8_t *a)
{
	int i;

	for (i = 0; i < 32; i ++) {
		d[i] ^= a[i];
	}
}

/*
 * Compute the Cascade construction on the AAD. This includes the
 * initialization step. The padded nonce is provided as input.
 */
static void
do_cascade_aad(uint8_t *r, const uint32_t *keybuf,
	const uint8_t *nonce, const uint8_t *buf, size_t len)
{
	uint8_t tmp[64];
	uint32_t kb2[32];
	size_t u, v, clen;

	memcpy(tmp, nonce, 32);
	memset(tmp + 32, 0, 32);
	saturnin_x2_block_encrypt(10, RC_10_2_X2, keybuf, tmp);
	xor32(tmp, nonce);
	for (u = 0; (u + 31) < len; u += 32) {
		saturnin_x2_key_expand_even(kb2, tmp);
		memcpy(tmp, buf + u, 32);
		saturnin_x2_block_encrypt(10, RC_10_2_X2, kb2, tmp);
		xor32(tmp, buf + u);
	}
	saturnin_x2_key_expand_even(kb2, tmp);
	clen = len - u;
	if (clen > 0) {
		memcpy(tmp, buf + u, clen);
	}
	tmp[clen] = 0x80;
	memset(tmp + clen + 1, 0, 31 - clen);
	saturnin_x2_block_encrypt(10, RC_10_3_X2, kb2, tmp);
	for (v = 0; v < clen; v ++) {
		tmp[v] ^= buf[u + v];
	}
	tmp[clen] ^= 0x80;
	memcpy(r, tmp, 32);
}

int
crypto_aead_encrypt(unsigned char *c, unsigned long long *clen,
	const unsigned char *m, unsigned long long mlen,
	const unsigned char *ad, unsigned long long adlen,
	const unsigned char *nsec,
	const unsigned char *npub,
	const unsigned char *k)
{
	uint32_t keybuf[32], keybuf2[32];
	uint8_t nonce[32], tag[32], tmp[64];
	uint8_t *buf;
	size_t u, len;
	int i;

	/*
	 * In this implementation, we limit the input length to less
	 * than 2^32-3 blocks (i.e. about 137.4 gigabytes), which allows
	 * us to keep the block counter on a single 32-bit integer.
	 */
	if ((mlen >> 5) >= 0xFFFFFFFD) {
		return -2;
	}
	len = (size_t)mlen;

	/*
	 * Pad the nonce into a 32-byte block.
	 */
	(void)nsec;
	memcpy(nonce, npub, 16);
	nonce[16] = 0x80;
	memset(nonce + 17, 0, 15);

	/*
	 * Move plaintext to ciphertext buffer.
	 */
	memmove(c, m, len);
	buf = (uint8_t *)c;

	/*
	 * Expand the key.
	 */
	saturnin_x2_key_expand_even(keybuf, (const uint8_t *)k);

	/*
	 * Process the AAD.
	 */
	do_cascade_aad(tag, keybuf, nonce, (const uint8_t *)ad, (size_t)adlen);

	/*
	 * First CTR block and last Cascade block must be processed out
	 * of the main loop, since the Cascade operates on the ciphertext.
	 */
	if (len >= 32) {
		memset(tmp + 32, 0, 32);
		memcpy(tmp, nonce, 32);
		tmp[31] = 0x01;
		saturnin_x2_block_encrypt(10,
			RC_10_combined_1_4_X2, keybuf, tmp);
		xor32(buf, tmp);
		memcpy(tmp + 32, tag, 32);

		/*
		 * Each loop iteration expects the current Cascade state
		 * in tmp[32..63].
		 */
		for (u = 32;;) {
			uint32_t ctr;

			memcpy(tmp, nonce, 28);
			ctr = (u >> 5) + 1;
			tmp[28] = (uint8_t)(ctr >> 24);
			tmp[29] = (uint8_t)(ctr >> 16);
			tmp[30] = (uint8_t)(ctr >> 8);
			tmp[31] = (uint8_t)ctr;
			saturnin_x2_key_expand_even(keybuf2, tmp + 32);
			for (i = 0; i < 32; i ++) {
				keybuf2[i] = (keybuf2[i] << 1) | keybuf[i];
			}
			memcpy(tmp + 32, buf + u - 32, 32);
			saturnin_x2_block_encrypt(10,
				RC_10_combined_1_4_X2, keybuf2, tmp);
			xor32(tmp + 32, buf + u - 32);
			if ((u + 31) < len) {
				xor32(buf + u, tmp);
				u += 32;
			} else {
				size_t v, rlen;

				rlen = len - u;
				for (v = 0; v < rlen; v ++) {
					buf[u + v] ^= tmp[v];
				}
				memcpy(tmp, buf + u, rlen);
				tmp[rlen] = 0x80;
				memset(tmp + rlen + 1, 0, 31 - rlen);
				break;
			}
		}

		/*
		 * On exit, the last partial ciphertext block, padded,
		 * is in tmp[0..31], and the current Cascade state is
		 * in tmp[32..63].
		 */
		memcpy(tag, tmp, 32);
		saturnin_x2_key_expand_even(keybuf2, tmp + 32);
		for (i = 0; i < 32; i ++) {
			keybuf2[i] <<= 1;
		}
		memcpy(tmp + 32, tmp, 32);
		saturnin_x2_block_encrypt(10,
			RC_10_combined_1_5_X2, keybuf2, tmp);
		xor32(tag, tmp + 32);
	} else {
		memset(tmp + 32, 0, 32);
		memcpy(tmp, nonce, 32);
		tmp[31] = 0x01;
		saturnin_x2_block_encrypt(10,
			RC_10_combined_1_4_X2, keybuf, tmp);
		for (u = 0; u < len; u ++) {
			tmp[u] ^= buf[u];
		}
		memcpy(buf, tmp, len);
		tmp[len] = 0x80;
		memset(tmp + len + 1, 0, 31 - len);
		saturnin_x2_key_expand_even(keybuf2, tag);
		for (i = 0; i < 32; i ++) {
			keybuf2[i] <<= 1;
		}
		memcpy(tag, tmp, 32);
		memcpy(tmp + 32, tmp, 32);
		saturnin_x2_block_encrypt(10,
			RC_10_combined_1_5_X2, keybuf2, tmp);
		xor32(tag, tmp + 32);
	}

	/*
	 * The tag goes at the end of the ciphertext.
	 */
	memcpy(c + len, tag, sizeof tag);
	*clen = len + sizeof tag;
	return 0;
}

int
crypto_aead_decrypt(unsigned char *m, unsigned long long *mlen,
	unsigned char *nsec,
	const unsigned char *c, unsigned long long clen,
	const unsigned char *ad, unsigned long long adlen,
	const unsigned char *npub,
	const unsigned char *k)
{
	uint32_t keybuf[32], keybuf2[32];
	uint8_t nonce[32], tag[32], received_tag[32], tmp[64];
	uint8_t *buf;
	uint32_t ctr;
	size_t u, v, len, rlen;
	unsigned tcc;
	int i;

	/*
	 * In this implementation, we limit the input length to less
	 * than 2^32-3 blocks (i.e. about 137.4 gigabytes), which allows
	 * us to keep the block counter on a single 32-bit integer.
	 */
	if ((clen >> 5) >= 0xFFFFFFFE) {
		return -2;
	}
	len = (size_t)clen;
	if (len < sizeof tag) {
		return -1;
	}
	len -= sizeof tag;

	/*
	 * Pad the nonce into a 32-byte block.
	 */
	(void)nsec;
	memcpy(nonce, npub, 16);
	nonce[16] = 0x80;
	memset(nonce + 17, 0, 15);

	/*
	 * Expand the key.
	 */
	saturnin_x2_key_expand_even(keybuf, (const uint8_t *)k);

	/*
	 * Process the AAD.
	 */
	do_cascade_aad(tag, keybuf, nonce, (const uint8_t *)ad, (size_t)adlen);

	/*
	 * Move the ciphertext to the plaintext (in-place decryption). We
	 * must first copy the tag to a safe place, in case of overlap.
	 */
	memcpy(received_tag, c + len, 32);
	memmove(m, c, len);
	buf = (uint8_t *)m;

	/*
	 * Do CTR+Cascade. At each iteration, we encrypt the current counter
	 * and the ciphertext block. The main loop processes only full
	 * blocks. Upon loop entry, the current Cascade state is expected
	 * in tmp[32..63].
	 */
	memcpy(tmp + 32, tag, 32);
	for (u = 0; (u + 31) < len; u += 32) {
		memcpy(tmp, nonce, 28);
		ctr = (u >> 5) + 1;
		tmp[28] = (uint8_t)(ctr >> 24);
		tmp[29] = (uint8_t)(ctr >> 16);
		tmp[30] = (uint8_t)(ctr >> 8);
		tmp[31] = (uint8_t)ctr;
		saturnin_x2_key_expand_even(keybuf2, tmp + 32);
		for (i = 0; i < 32; i ++) {
			keybuf2[i] = (keybuf2[i] << 1) | keybuf[i];
		}
		memcpy(tmp + 32, buf + u, 32);
		saturnin_x2_block_encrypt(10,
			RC_10_combined_1_4_X2, keybuf2, tmp);
		xor32(tmp + 32, buf + u);
		xor32(buf + u, tmp);
	}
	memcpy(tmp, nonce, 28);
	ctr = (u >> 5) + 1;
	tmp[28] = (uint8_t)(ctr >> 24);
	tmp[29] = (uint8_t)(ctr >> 16);
	tmp[30] = (uint8_t)(ctr >> 8);
	tmp[31] = (uint8_t)ctr;
	saturnin_x2_key_expand_even(keybuf2, tmp + 32);
	for (i = 0; i < 32; i ++) {
		keybuf2[i] = (keybuf2[i] << 1) | keybuf[i];
	}
	rlen = len - u;
	if (rlen > 0) {
		memcpy(tmp + 32, buf + u, rlen);
	}
	tmp[32 + rlen] = 0x80;
	memset(tmp + 32 + rlen + 1, 0, 31 - rlen);
	memcpy(tag, tmp + 32, 32);
	saturnin_x2_block_encrypt(10, RC_10_combined_1_5_X2, keybuf2, tmp);
	for (v = 0; v < rlen; v ++) {
		buf[u + v] ^= tmp[v];
	}
	xor32(tag, tmp + 32);

	*mlen = len;

	/*
	 * Compare the computed tag with the received value. If they
	 * match, tcc will be 0; otherwise, tcc will be 1.
	 */
	tcc = 0;
	for (u = 0; u < sizeof tag; u ++) {
		tcc |= tag[u] ^ received_tag[u];
	}
	tcc = (tcc + 0xFF) >> 8;

	/*
	 * Returned value is 0 on success (tags match), -1 on error.
	 */
	return -(int)tcc;
}
