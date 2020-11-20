/* ======================================================================== */
/*
 * Saturnin-CTR-Cascade (NIST API).
 *
 * bs32: this implementation uses the "bitslice-32" representation in
 * which the sixteen 16-bit state registres are grouped pairwise into
 * 32-bit words.
 */

#include "crypto_aead.h"

#include <string.h>
#include <stdint.h>

/*
 * We represent the sixteen 16-bit registers r0..r15 into eight 32-bit
 * variables q0..q7:
 *
 *   q0 = r0 | (r8 << 16)
 *   q1 = r1 | (r9 << 16)
 *   ...
 *   q7 = r7 | (r15 << 16)
 *
 * This is done so because S-box for r0..r3 and r8..r11 is the same;
 * similarly for S-box for r4..r7 and r12..r15.
 */

#define DECL_STATE   \
	uint32_t q0, q1, q2, q3, q4, q5, q6, q7;

#define DEC256(b, src)   do { \
		b ## 0 = (uint32_t)(src)[ 0] \
			| ((uint32_t)(src)[ 1] << 8) \
			| ((uint32_t)(src)[16] << 16) \
			| ((uint32_t)(src)[17] << 24); \
		b ## 1 = (uint32_t)(src)[ 2] \
			| ((uint32_t)(src)[ 3] << 8) \
			| ((uint32_t)(src)[18] << 16) \
			| ((uint32_t)(src)[19] << 24); \
		b ## 2 = (uint32_t)(src)[ 4] \
			| ((uint32_t)(src)[ 5] << 8) \
			| ((uint32_t)(src)[20] << 16) \
			| ((uint32_t)(src)[21] << 24); \
		b ## 3 = (uint32_t)(src)[ 6] \
			| ((uint32_t)(src)[ 7] << 8) \
			| ((uint32_t)(src)[22] << 16) \
			| ((uint32_t)(src)[23] << 24); \
		b ## 4 = (uint32_t)(src)[ 8] \
			| ((uint32_t)(src)[ 9] << 8) \
			| ((uint32_t)(src)[24] << 16) \
			| ((uint32_t)(src)[25] << 24); \
		b ## 5 = (uint32_t)(src)[10] \
			| ((uint32_t)(src)[11] << 8) \
			| ((uint32_t)(src)[26] << 16) \
			| ((uint32_t)(src)[27] << 24); \
		b ## 6 = (uint32_t)(src)[12] \
			| ((uint32_t)(src)[13] << 8) \
			| ((uint32_t)(src)[28] << 16) \
			| ((uint32_t)(src)[29] << 24); \
		b ## 7 = (uint32_t)(src)[14] \
			| ((uint32_t)(src)[15] << 8) \
			| ((uint32_t)(src)[30] << 16) \
			| ((uint32_t)(src)[31] << 24); \
	} while (0)

#define ENC256(b, dst)   do { \
		(dst)[ 0] = (uint8_t)b ## 0; \
		(dst)[ 1] = (uint8_t)(b ## 0 >> 8); \
		(dst)[16] = (uint8_t)(b ## 0 >> 16); \
		(dst)[17] = (uint8_t)(b ## 0 >> 24); \
		(dst)[ 2] = (uint8_t)b ## 1; \
		(dst)[ 3] = (uint8_t)(b ## 1 >> 8); \
		(dst)[18] = (uint8_t)(b ## 1 >> 16); \
		(dst)[19] = (uint8_t)(b ## 1 >> 24); \
		(dst)[ 4] = (uint8_t)b ## 2; \
		(dst)[ 5] = (uint8_t)(b ## 2 >> 8); \
		(dst)[20] = (uint8_t)(b ## 2 >> 16); \
		(dst)[21] = (uint8_t)(b ## 2 >> 24); \
		(dst)[ 6] = (uint8_t)b ## 3; \
		(dst)[ 7] = (uint8_t)(b ## 3 >> 8); \
		(dst)[22] = (uint8_t)(b ## 3 >> 16); \
		(dst)[23] = (uint8_t)(b ## 3 >> 24); \
		(dst)[ 8] = (uint8_t)b ## 4; \
		(dst)[ 9] = (uint8_t)(b ## 4 >> 8); \
		(dst)[24] = (uint8_t)(b ## 4 >> 16); \
		(dst)[25] = (uint8_t)(b ## 4 >> 24); \
		(dst)[10] = (uint8_t)b ## 5; \
		(dst)[11] = (uint8_t)(b ## 5 >> 8); \
		(dst)[26] = (uint8_t)(b ## 5 >> 16); \
		(dst)[27] = (uint8_t)(b ## 5 >> 24); \
		(dst)[12] = (uint8_t)b ## 6; \
		(dst)[13] = (uint8_t)(b ## 6 >> 8); \
		(dst)[28] = (uint8_t)(b ## 6 >> 16); \
		(dst)[29] = (uint8_t)(b ## 6 >> 24); \
		(dst)[14] = (uint8_t)b ## 7; \
		(dst)[15] = (uint8_t)(b ## 7 >> 8); \
		(dst)[30] = (uint8_t)(b ## 7 >> 16); \
		(dst)[31] = (uint8_t)(b ## 7 >> 24); \
	} while (0)

#define SBOX   do { \
		uint32_t a, b, c, d; \
		a = q0; \
		b = q1; \
		c = q2; \
		d = q3; \
		a ^= b & c; \
		b ^= a | d; \
		d ^= b | c; \
		c ^= b & d; \
		b ^= a | c; \
		a ^= b | d; \
		q0 = b; \
		q1 = c; \
		q2 = d; \
		q3 = a; \
		a = q4; \
		b = q5; \
		c = q6; \
		d = q7; \
		a ^= b & c; \
		b ^= a | d; \
		d ^= b | c; \
		c ^= b & d; \
		b ^= a | c; \
		a ^= b | d; \
		q4 = d; \
		q5 = b; \
		q6 = a; \
		q7 = c; \
	} while (0)

#define SBOX_INV   do { \
		uint32_t a, b, c, d; \
		b = q0; \
		c = q1; \
		d = q2; \
		a = q3; \
		a ^= b | d; \
		b ^= a | c; \
		c ^= b & d; \
		d ^= b | c; \
		b ^= a | d; \
		a ^= b & c; \
		q0 = a; \
		q1 = b; \
		q2 = c; \
		q3 = d; \
		d = q4; \
		b = q5; \
		a = q6; \
		c = q7; \
		a ^= b | d; \
		b ^= a | c; \
		c ^= b & d; \
		d ^= b | c; \
		b ^= a | d; \
		a ^= b & c; \
		q4 = a; \
		q5 = b; \
		q6 = c; \
		q7 = d; \
	} while (0)

#define MUL(t0, t1, t2, t3)   do { \
		uint32_t mul_tmp = (t0); \
		(t0) = (t1); \
		(t1) = (t2); \
		(t2) = (t3); \
		(t3) = mul_tmp ^ (t0); \
	} while (0)

#define MUL_INV(t0, t1, t2, t3)   do { \
		uint32_t mul_tmp = (t3); \
		(t3) = (t2); \
		(t2) = (t1); \
		(t1) = (t0); \
		(t0) = mul_tmp ^ (t1); \
	} while (0)

#define SW(x)   (((x) >> 16) | ((x) << 16))

#define MDS   do { \
		q0 ^= q4; q1 ^= q5; q2 ^= q6; q3 ^= q7; \
		MUL(q4, q5, q6, q7); \
		q4 ^= SW(q0); q5 ^= SW(q1); q6 ^= SW(q2); q7 ^= SW(q3); \
		MUL(q0, q1, q2, q3); \
		MUL(q0, q1, q2, q3); \
		q0 ^= q4; q1 ^= q5; q2 ^= q6; q3 ^= q7; \
		q4 ^= SW(q0); q5 ^= SW(q1); q6 ^= SW(q2); q7 ^= SW(q3); \
	} while (0)

#define MDS_INV   do { \
		q4 ^= SW(q0); q5 ^= SW(q1); q6 ^= SW(q2); q7 ^= SW(q3); \
		q0 ^= q4; q1 ^= q5; q2 ^= q6; q3 ^= q7; \
		MUL_INV(q0, q1, q2, q3); \
		MUL_INV(q0, q1, q2, q3); \
		q4 ^= SW(q0); q5 ^= SW(q1); q6 ^= SW(q2); q7 ^= SW(q3); \
		MUL_INV(q4, q5, q6, q7); \
		q0 ^= q4; q1 ^= q5; q2 ^= q6; q3 ^= q7; \
	} while (0)

#define SR_SLICE   do { \
		q0 = (q0 & 0xFFFF) | ((q0 & 0x33330000) << 2) \
			| ((q0 >> 2) & 0x33330000); \
		q1 = (q1 & 0xFFFF) | ((q1 & 0x33330000) << 2) \
			| ((q1 >> 2) & 0x33330000); \
		q2 = (q2 & 0xFFFF) | ((q2 & 0x33330000) << 2) \
			| ((q2 >> 2) & 0x33330000); \
		q3 = (q3 & 0xFFFF) | ((q3 & 0x33330000) << 2) \
			| ((q3 >> 2) & 0x33330000); \
		q4 = ((q4 & 0x00007777) << 1) | ((q4 >> 3) & 0x00001111) \
			| ((q4 & 0x11110000) << 3) | ((q4 >> 1) & 0x77770000); \
		q5 = ((q5 & 0x00007777) << 1) | ((q5 >> 3) & 0x00001111) \
			| ((q5 & 0x11110000) << 3) | ((q5 >> 1) & 0x77770000); \
		q6 = ((q6 & 0x00007777) << 1) | ((q6 >> 3) & 0x00001111) \
			| ((q6 & 0x11110000) << 3) | ((q6 >> 1) & 0x77770000); \
		q7 = ((q7 & 0x00007777) << 1) | ((q7 >> 3) & 0x00001111) \
			| ((q7 & 0x11110000) << 3) | ((q7 >> 1) & 0x77770000); \
	} while (0)

#define SR_SLICE_INV   do { \
		q0 = (q0 & 0xFFFF) | ((q0 & 0x33330000) << 2) \
			| ((q0 >> 2) & 0x33330000); \
		q1 = (q1 & 0xFFFF) | ((q1 & 0x33330000) << 2) \
			| ((q1 >> 2) & 0x33330000); \
		q2 = (q2 & 0xFFFF) | ((q2 & 0x33330000) << 2) \
			| ((q2 >> 2) & 0x33330000); \
		q3 = (q3 & 0xFFFF) | ((q3 & 0x33330000) << 2) \
			| ((q3 >> 2) & 0x33330000); \
		q4 = ((q4 & 0x00001111) << 3) | ((q4 >> 1) & 0x00007777) \
			| ((q4 & 0x77770000) << 1) | ((q4 >> 3) & 0x11110000); \
		q5 = ((q5 & 0x00001111) << 3) | ((q5 >> 1) & 0x00007777) \
			| ((q5 & 0x77770000) << 1) | ((q5 >> 3) & 0x11110000); \
		q6 = ((q6 & 0x00001111) << 3) | ((q6 >> 1) & 0x00007777) \
			| ((q6 & 0x77770000) << 1) | ((q6 >> 3) & 0x11110000); \
		q7 = ((q7 & 0x00001111) << 3) | ((q7 >> 1) & 0x00007777) \
			| ((q7 & 0x77770000) << 1) | ((q7 >> 3) & 0x11110000); \
	} while (0)

#define SR_SHEET   do { \
		q0 = (q0 & 0xFFFF) | ((q0 & 0x00FF0000) << 8) \
			| ((q0 >> 8) & 0x00FF0000); \
		q1 = (q1 & 0xFFFF) | ((q1 & 0x00FF0000) << 8) \
			| ((q1 >> 8) & 0x00FF0000); \
		q2 = (q2 & 0xFFFF) | ((q2 & 0x00FF0000) << 8) \
			| ((q2 >> 8) & 0x00FF0000); \
		q3 = (q3 & 0xFFFF) | ((q3 & 0x00FF0000) << 8) \
			| ((q3 >> 8) & 0x00FF0000); \
		q4 = ((q4 & 0x00000FFF) << 4) | ((q4 >> 12) & 0x0000000F) \
			| ((q4 & 0x000F0000) << 12) | ((q4 >> 4) & 0x0FFF0000);\
		q5 = ((q5 & 0x00000FFF) << 4) | ((q5 >> 12) & 0x0000000F) \
			| ((q5 & 0x000F0000) << 12) | ((q5 >> 4) & 0x0FFF0000);\
		q6 = ((q6 & 0x00000FFF) << 4) | ((q6 >> 12) & 0x0000000F) \
			| ((q6 & 0x000F0000) << 12) | ((q6 >> 4) & 0x0FFF0000);\
		q7 = ((q7 & 0x00000FFF) << 4) | ((q7 >> 12) & 0x0000000F) \
			| ((q7 & 0x000F0000) << 12) | ((q7 >> 4) & 0x0FFF0000);\
	} while (0)

#define SR_SHEET_INV   do { \
		q0 = (q0 & 0xFFFF) | ((q0 & 0x00FF0000) << 8) \
			| ((q0 >> 8) & 0x00FF0000); \
		q1 = (q1 & 0xFFFF) | ((q1 & 0x00FF0000) << 8) \
			| ((q1 >> 8) & 0x00FF0000); \
		q2 = (q2 & 0xFFFF) | ((q2 & 0x00FF0000) << 8) \
			| ((q2 >> 8) & 0x00FF0000); \
		q3 = (q3 & 0xFFFF) | ((q3 & 0x00FF0000) << 8) \
			| ((q3 >> 8) & 0x00FF0000); \
		q4 = ((q4 & 0x0000000F) << 12) | ((q4 >> 4) & 0x00000FFF) \
			| ((q4 & 0x0FFF0000) << 4) | ((q4 >> 12) & 0x000F0000);\
		q5 = ((q5 & 0x0000000F) << 12) | ((q5 >> 4) & 0x00000FFF) \
			| ((q5 & 0x0FFF0000) << 4) | ((q5 >> 12) & 0x000F0000);\
		q6 = ((q6 & 0x0000000F) << 12) | ((q6 >> 4) & 0x00000FFF) \
			| ((q6 & 0x0FFF0000) << 4) | ((q6 >> 12) & 0x000F0000);\
		q7 = ((q7 & 0x0000000F) << 12) | ((q7 >> 4) & 0x00000FFF) \
			| ((q7 & 0x0FFF0000) << 4) | ((q7 >> 12) & 0x000F0000);\
	} while (0)

#define XOR_KEY   do { \
		q0 ^= keybuf[0]; \
		q1 ^= keybuf[1]; \
		q2 ^= keybuf[2]; \
		q3 ^= keybuf[3]; \
		q4 ^= keybuf[4]; \
		q5 ^= keybuf[5]; \
		q6 ^= keybuf[6]; \
		q7 ^= keybuf[7]; \
	} while (0)

#define XOR_KEY_ROTATED   do { \
		q0 ^= keybuf[ 8]; \
		q1 ^= keybuf[ 9]; \
		q2 ^= keybuf[10]; \
		q3 ^= keybuf[11]; \
		q4 ^= keybuf[12]; \
		q5 ^= keybuf[13]; \
		q6 ^= keybuf[14]; \
		q7 ^= keybuf[15]; \
	} while (0)

/*
 * For Saturnin-CTR-Cascade: R = 10; D = 1, 2, 3, 4 or 5.
 */

static const uint32_t RC_10_1[] = {
	0x4EB026C2, 0x90595303, 0xAA8FE632, 0xFE928A92,
	0x4115A419, 0x93539532, 0x5DB1CC4E, 0x541515CA,
	0xBD1F55A8, 0x5A6E1A0D
};

static const uint32_t RC_10_2[] = {
	0x4E4526B5, 0xA3565FF0, 0x0F8F20D8, 0x0B54BEE1,
	0x7D1A6C9D, 0x17A6280A, 0xAA46C986, 0xC1199062,
	0x182C5CDE, 0xA00D53FE
};

static const uint32_t RC_10_3[] = {
	0x4E162698, 0xB2535BA1, 0x6C8F9D65, 0x5816AD30,
	0x691FD4FA, 0x6BF5BCF9, 0xF8EB3525, 0xB21DECFA,
	0x7B3DA417, 0xF62C94B4
};

static const uint32_t RC_10_4[] = {
	0x4FAF265B, 0xC5484616, 0x45DCAD21, 0xE08BD607,
	0x0504FDB8, 0x1E1F5257, 0x45FBC216, 0xEB529B1F,
	0x52194E32, 0x5498C018
};

static const uint32_t RC_10_5[] = {
	0x4FFC2676, 0xD44D4247, 0x26DC109C, 0xB3C9C5D6,
	0x110145DF, 0x624CC6A4, 0x17563EB5, 0x9856E787,
	0x3108B6FB, 0x02B90752
};

/*
 * Decode a key into 32-bit words (with bitslice-32 encoding, and
 * followed by the rotated key).
 */
static void
saturnin_key_expand(uint32_t *keybuf, const uint8_t *key)
{
	int i;

	for (i = 0; i < 8; i ++) {
		uint32_t w;

		w = (uint32_t)key[(i << 1) + 0]
			| ((uint32_t)key[(i << 1) + 1] << 8)
			| ((uint32_t)key[(i << 1) + 16] << 16)
			| ((uint32_t)key[(i << 1) + 17] << 24);
		keybuf[i] = w;
		keybuf[i + 8] = ((w & 0x001F001F) << 11)
			| ((w >> 5) & 0x07FF07FF);
	}
}

/*
 * Perform one Saturnin block encryption.
 *   R        number of super-rounds (0 to 31)
 *   rc       round constants (depends on R and D)
 *   keybuf   key and rotated key (16 words = 64 bytes)
 *   buf      block to encrypt
 * The encrypted block is written back in 'buf'.
 */
static void
saturnin_block_encrypt(int R, const uint32_t *rc,
	const uint32_t *keybuf, uint8_t *buf)
{
	DECL_STATE
	int i;

	/*
	 * Decode data into the registers.
	 */
	DEC256(q, buf);

	XOR_KEY;

	/*
	 * Run all rounds (two rounds per super-round, two super-rounds
	 * per loop iteration).
	 */
	for (i = 0; i < R; i += 2) {
		/*
		 * Even round.
		 */
		SBOX;
		MDS;

		/*
		 * Odd round r = 1 mod 4.
		 */
		SBOX;
		SR_SLICE;
		MDS;
		SR_SLICE_INV;
		q0 ^= rc[i + 0];
		XOR_KEY_ROTATED;

		/*
		 * Even round.
		 */
		SBOX;
		MDS;

		/*
		 * Odd round r = 3 mod 4.
		 */
		SBOX;
		SR_SHEET;
		MDS;
		SR_SHEET_INV;
		q0 ^= rc[i + 1];
		XOR_KEY;
	}

	/*
	 * Encode back the result.
	 */
	ENC256(q, buf);
}

/*
 * Compute the initial state for the Cascade construction: input block
 * is the padded nonce. r[] and nonce[] MUST NOT overlap.
 */
static void
do_cascade_init(uint8_t *r, const uint32_t *keybuf, const uint8_t *nonce)
{
	size_t u;

	memcpy(r, nonce, 32);
	saturnin_block_encrypt(10, RC_10_2, keybuf, r);
	for (u = 0; u < 32; u ++) {
		r[u] ^= nonce[u];
	}
}

/*
 * Compute the Cascade construction on some data (AAD or ciphertext),
 * using the provided domain parameters. For the AAD, the initial
 * state is assumed to be already initialized (with do_cascade_init()).
 * Padding is applied.
 */
static void
do_cascade(uint8_t *r, const uint32_t *rc1, const uint32_t *rc2,
	const uint8_t *buf, size_t len)
{
	size_t u;

	u = 0;
	for (;;) {
		uint32_t keybuf[16];
		size_t clen, v;
		const uint32_t *rc;
		uint8_t m[32], t[32];

		rc = rc1;
		clen = len - u;
		if (clen >= sizeof t) {
			memcpy(t, buf + u, sizeof t);
			u += sizeof t;
		} else {
			memcpy(t, buf + u, clen);
			t[clen] = 0x80;
			memset(t + clen + 1, 0, (sizeof t) - clen - 1);
			rc = rc2;
		}
		memcpy(m, t, sizeof t);
		saturnin_key_expand(keybuf, r);
		saturnin_block_encrypt(10, rc, keybuf, m);
		for (v = 0; v < sizeof t; v ++) {
			r[v] = m[v] ^ t[v];
		}
		if (rc == rc2) {
			break;
		}
	}
}

/*
 * Compute CTR encryption/decryption on data (in-place). This function
 * assumes that the number of blocks is less than 2^32-2.
 */
static void
do_ctr(const uint32_t *keybuf, const uint8_t *nonce, uint8_t *buf, size_t len)
{
	uint32_t cc;
	size_t u;

	/*
	 * Counter starts at 1, because counter 0 is used for the
	 * Cascade initial block.
	 */
	cc = 1;
	u = 0;
	while (u < len) {
		uint8_t t[32];
		size_t v;

		memcpy(t, nonce, 16);
		t[16] = 0x80;
		memset(t + 17, 0, 11);
		t[28] = (uint8_t)(cc >> 24);
		t[29] = (uint8_t)(cc >> 16);
		t[30] = (uint8_t)(cc >> 8);
		t[31] = (uint8_t)cc;
		saturnin_block_encrypt(10, RC_10_1, keybuf, t);
		for (v = 0; (v < sizeof t) && (u < len); v ++, u ++) {
			buf[u] ^= t[v];
		}
		cc ++;
	}
}

int
crypto_aead_encrypt(unsigned char *c, unsigned long long *clen,
	const unsigned char *m, unsigned long long mlen,
	const unsigned char *ad, unsigned long long adlen,
	const unsigned char *nsec,
	const unsigned char *npub,
	const unsigned char *k)
{
	uint32_t keybuf[16];
	uint8_t nonce[32], tag[32];
	size_t len;

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
	 * Expand the key.
	 */
	saturnin_key_expand(keybuf, (const uint8_t *)k);

	/*
	 * Encrypt the plaintext with CTR.
	 */
	memmove(c, m, len);
	do_ctr(keybuf, nonce, (uint8_t *)c, len);

	/*
	 * Do the Cascade.
	 */
	do_cascade_init(tag, keybuf, nonce);
	do_cascade(tag, RC_10_2, RC_10_3, (const uint8_t *)ad, (size_t)adlen);
	do_cascade(tag, RC_10_4, RC_10_5, (const uint8_t *)c, len);

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
	uint32_t keybuf[16];
	uint8_t nonce[32], tag[32];
	size_t u, len;
	unsigned tcc;

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
	saturnin_key_expand(keybuf, (const uint8_t *)k);

	/*
	 * Do the Cascade.
	 */
	do_cascade_init(tag, keybuf, nonce);
	do_cascade(tag, RC_10_2, RC_10_3, (const uint8_t *)ad, (size_t)adlen);
	do_cascade(tag, RC_10_4, RC_10_5, (const uint8_t *)c, len);

	/*
	 * Compare the computed tag with the received value. If they
	 * match, tcc will be 0; otherwise, tcc will be 1.
	 */
	tcc = 0;
	for (u = 0; u < sizeof tag; u ++) {
		tcc |= tag[u] ^ c[len + u];
	}
	tcc = (tcc + 0xFF) >> 8;

	/*
	 * Decrypt the ciphertext with CTR.
	 */
	memmove(m, c, len);
	do_ctr(keybuf, nonce, (uint8_t *)m, len);
	*mlen = len;

	/*
	 * Returned value is 0 on success (tags match), -1 on error.
	 */
	return -(int)tcc;
}
