/* ======================================================================== */
/*
 * Saturnin-CTR-Cascade (NIST API).
 *
 * bs64: this implementation uses the same representation as bs32, but
 * fits two instances in parallel in 64-bit registers (one instance uses
 * the low halves of the CPU registers, the other uses the high half).
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
 * The q* values from two Saturnin instances are furthermore grouped
 * into the 64-bit words qw0 to qw7.
 */

#define DECL_STATE   \
	uint64_t qw0, qw1, qw2, qw3, qw4, qw5, qw6, qw7;

#define DEC64LE(q, src)   do { \
		q = (uint64_t)(src)[0] \
			| ((uint64_t)(src)[1] <<  8) \
			| ((uint64_t)(src)[2] << 16) \
			| ((uint64_t)(src)[3] << 24) \
			| ((uint64_t)(src)[4] << 32) \
			| ((uint64_t)(src)[5] << 40) \
			| ((uint64_t)(src)[6] << 48) \
			| ((uint64_t)(src)[7] << 56); \
	} while (0)

#define DEC512(src)   do { \
		uint64_t td0, td1, td2, td3, td4, td5, td6, td7; \
		DEC64LE(td0, (src)); \
		DEC64LE(td1, (src) +  8); \
		DEC64LE(td2, (src) + 16); \
		DEC64LE(td3, (src) + 24); \
		DEC64LE(td4, (src) + 32); \
		DEC64LE(td5, (src) + 40); \
		DEC64LE(td6, (src) + 48); \
		DEC64LE(td7, (src) + 56); \
		qw0 = (td0 & 0xFFFF) \
			| ((td2 & 0xFFFF) << 16) \
			| ((td4 & 0xFFFF) << 32) \
			| (td6 << 48); \
		qw1 = ((td0 & 0xFFFF0000) >> 16) \
			| (td2 & 0xFFFF0000) \
			| ((td4 & 0xFFFF0000) << 16) \
			| ((td6 & 0xFFFF0000) << 32); \
		qw2 = ((td0 & 0xFFFF00000000) >> 32) \
			| ((td2 & 0xFFFF00000000) >> 16) \
			| (td4 & 0xFFFF00000000) \
			| ((td6 & 0xFFFF00000000) << 16); \
		qw3 = (td0 >> 48) \
			| ((td2 & 0xFFFF000000000000) >> 32) \
			| ((td4 & 0xFFFF000000000000) >> 16) \
			| (td6 & 0xFFFF000000000000); \
		qw4 = (td1 & 0xFFFF) \
			| ((td3 & 0xFFFF) << 16) \
			| ((td5 & 0xFFFF) << 32) \
			| (td7 << 48); \
		qw5 = ((td1 & 0xFFFF0000) >> 16) \
			| (td3 & 0xFFFF0000) \
			| ((td5 & 0xFFFF0000) << 16) \
			| ((td7 & 0xFFFF0000) << 32); \
		qw6 = ((td1 & 0xFFFF00000000) >> 32) \
			| ((td3 & 0xFFFF00000000) >> 16) \
			| (td5 & 0xFFFF00000000) \
			| ((td7 & 0xFFFF00000000) << 16); \
		qw7 = (td1 >> 48) \
			| ((td3 & 0xFFFF000000000000) >> 32) \
			| ((td5 & 0xFFFF000000000000) >> 16) \
			| (td7 & 0xFFFF000000000000); \
	} while (0)

#define ENC64LE(dst, q)   do { \
		(dst)[0] = (uint8_t)(q); \
		(dst)[1] = (uint8_t)((q) >>  8); \
		(dst)[2] = (uint8_t)((q) >> 16); \
		(dst)[3] = (uint8_t)((q) >> 24); \
		(dst)[4] = (uint8_t)((q) >> 32); \
		(dst)[5] = (uint8_t)((q) >> 40); \
		(dst)[6] = (uint8_t)((q) >> 48); \
		(dst)[7] = (uint8_t)((q) >> 56); \
	} while (0)

#define ENC512(dst)   do { \
		uint64_t td0, td1, td2, td3, td4, td5, td6, td7; \
		td0 = (qw0 & 0xFFFF) \
			| ((qw1 & 0xFFFF) << 16) \
			| ((qw2 & 0xFFFF) << 32) \
			| (qw3 << 48); \
		td1 = (qw4 & 0xFFFF) \
			| ((qw5 & 0xFFFF) << 16) \
			| ((qw6 & 0xFFFF) << 32) \
			| (qw7 << 48); \
		td2 = ((qw0 & 0xFFFF0000) >> 16) \
			| (qw1 & 0xFFFF0000) \
			| ((qw2 & 0xFFFF0000) << 16) \
			| ((qw3 & 0xFFFF0000) << 32); \
		td3 = ((qw4 & 0xFFFF0000) >> 16) \
			| (qw5 & 0xFFFF0000) \
			| ((qw6 & 0xFFFF0000) << 16) \
			| ((qw7 & 0xFFFF0000) << 32); \
		td4 = ((qw0 & 0xFFFF00000000) >> 32) \
			| ((qw1 & 0xFFFF00000000) >> 16) \
			| (qw2 & 0xFFFF00000000) \
			| ((qw3 & 0xFFFF00000000) << 16); \
		td5 = ((qw4 & 0xFFFF00000000) >> 32) \
			| ((qw5 & 0xFFFF00000000) >> 16) \
			| (qw6 & 0xFFFF00000000) \
			| ((qw7 & 0xFFFF00000000) << 16); \
		td6 = (qw0 >> 48) \
			| ((qw1 & 0xFFFF000000000000) >> 32) \
			| ((qw2 & 0xFFFF000000000000) >> 16) \
			| (qw3 & 0xFFFF000000000000); \
		td7 = (qw4 >> 48) \
			| ((qw5 & 0xFFFF000000000000) >> 32) \
			| ((qw6 & 0xFFFF000000000000) >> 16) \
			| (qw7 & 0xFFFF000000000000); \
		ENC64LE((dst), td0); \
		ENC64LE((dst) +  8, td1); \
		ENC64LE((dst) + 16, td2); \
		ENC64LE((dst) + 24, td3); \
		ENC64LE((dst) + 32, td4); \
		ENC64LE((dst) + 40, td5); \
		ENC64LE((dst) + 48, td6); \
		ENC64LE((dst) + 56, td7); \
	} while (0)

#define SBOX   do { \
		uint64_t a, b, c, d; \
		a = qw0; \
		b = qw1; \
		c = qw2; \
		d = qw3; \
		a ^= b & c; \
		b ^= a | d; \
		d ^= b | c; \
		c ^= b & d; \
		b ^= a | c; \
		a ^= b | d; \
		qw0 = b; \
		qw1 = c; \
		qw2 = d; \
		qw3 = a; \
		a = qw4; \
		b = qw5; \
		c = qw6; \
		d = qw7; \
		a ^= b & c; \
		b ^= a | d; \
		d ^= b | c; \
		c ^= b & d; \
		b ^= a | c; \
		a ^= b | d; \
		qw4 = d; \
		qw5 = b; \
		qw6 = a; \
		qw7 = c; \
	} while (0)

#define SBOX_INV   do { \
		uint64_t a, b, c, d; \
		b = qw0; \
		c = qw1; \
		d = qw2; \
		a = qw3; \
		a ^= b | d; \
		b ^= a | c; \
		c ^= b & d; \
		d ^= b | c; \
		b ^= a | d; \
		a ^= b & c; \
		qw0 = a; \
		qw1 = b; \
		qw2 = c; \
		qw3 = d; \
		d = qw4; \
		b = qw5; \
		a = qw6; \
		c = qw7; \
		a ^= b | d; \
		b ^= a | c; \
		c ^= b & d; \
		d ^= b | c; \
		b ^= a | d; \
		a ^= b & c; \
		qw4 = a; \
		qw5 = b; \
		qw6 = c; \
		qw7 = d; \
	} while (0)

#define MUL(t0, t1, t2, t3)   do { \
		uint64_t mul_tmp = (t0); \
		(t0) = (t1); \
		(t1) = (t2); \
		(t2) = (t3); \
		(t3) = mul_tmp ^ (t0); \
	} while (0)

#define MUL_INV(t0, t1, t2, t3)   do { \
		uint64_t mul_tmp = (t3); \
		(t3) = (t2); \
		(t2) = (t1); \
		(t1) = (t0); \
		(t0) = mul_tmp ^ (t1); \
	} while (0)

#define SW(x)  ((((x) >> 16) & 0xFFFF0000FFFF) | (((x) & 0xFFFF0000FFFF) << 16))

#define MDS   do { \
		qw0 ^= qw4; qw1 ^= qw5; qw2 ^= qw6; qw3 ^= qw7; \
		MUL(qw4, qw5, qw6, qw7); \
		qw4 ^= SW(qw0); qw5 ^= SW(qw1); qw6 ^= SW(qw2); qw7 ^= SW(qw3);\
		MUL(qw0, qw1, qw2, qw3); \
		MUL(qw0, qw1, qw2, qw3); \
		qw0 ^= qw4; qw1 ^= qw5; qw2 ^= qw6; qw3 ^= qw7; \
		qw4 ^= SW(qw0); qw5 ^= SW(qw1); qw6 ^= SW(qw2); qw7 ^= SW(qw3);\
	} while (0)

#define MDS_INV   do { \
		qw4 ^= SW(qw0); qw5 ^= SW(qw1); qw6 ^= SW(qw2); qw7 ^= SW(qw3);\
		qw0 ^= qw4; qw1 ^= qw5; qw2 ^= qw6; qw3 ^= qw7; \
		MUL_INV(qw0, qw1, qw2, qw3); \
		MUL_INV(qw0, qw1, qw2, qw3); \
		qw4 ^= SW(qw0); qw5 ^= SW(qw1); qw6 ^= SW(qw2); qw7 ^= SW(qw3);\
		MUL_INV(qw4, qw5, qw6, qw7); \
		qw0 ^= qw4; qw1 ^= qw5; qw2 ^= qw6; qw3 ^= qw7; \
	} while (0)

#define SR_SLICE   do { \
		qw0 = (qw0 & 0x0000FFFF0000FFFF) \
			| ((qw0 & 0x3333000033330000) << 2) \
			| ((qw0 >> 2) & 0x3333000033330000); \
		qw1 = (qw1 & 0x0000FFFF0000FFFF) \
			| ((qw1 & 0x3333000033330000) << 2) \
			| ((qw1 >> 2) & 0x3333000033330000); \
		qw2 = (qw2 & 0x0000FFFF0000FFFF) \
			| ((qw2 & 0x3333000033330000) << 2) \
			| ((qw2 >> 2) & 0x3333000033330000); \
		qw3 = (qw3 & 0x0000FFFF0000FFFF) \
			| ((qw3 & 0x3333000033330000) << 2) \
			| ((qw3 >> 2) & 0x3333000033330000); \
		qw4 = ((qw4 & 0x0000777700007777) << 1) \
			| ((qw4 >> 3) & 0x0000111100001111) \
			| ((qw4 & 0x1111000011110000) << 3) \
			| ((qw4 >> 1) & 0x7777000077770000); \
		qw5 = ((qw5 & 0x0000777700007777) << 1) \
			| ((qw5 >> 3) & 0x0000111100001111) \
			| ((qw5 & 0x1111000011110000) << 3) \
			| ((qw5 >> 1) & 0x7777000077770000); \
		qw6 = ((qw6 & 0x0000777700007777) << 1) \
			| ((qw6 >> 3) & 0x0000111100001111) \
			| ((qw6 & 0x1111000011110000) << 3) \
			| ((qw6 >> 1) & 0x7777000077770000); \
		qw7 = ((qw7 & 0x0000777700007777) << 1) \
			| ((qw7 >> 3) & 0x0000111100001111) \
			| ((qw7 & 0x1111000011110000) << 3) \
			| ((qw7 >> 1) & 0x7777000077770000); \
	} while (0)

#define SR_SLICE_INV   do { \
		qw0 = (qw0 & 0x0000FFFF0000FFFF) \
			| ((qw0 & 0x3333000033330000) << 2) \
			| ((qw0 >> 2) & 0x3333000033330000); \
		qw1 = (qw1 & 0x0000FFFF0000FFFF) \
			| ((qw1 & 0x3333000033330000) << 2) \
			| ((qw1 >> 2) & 0x3333000033330000); \
		qw2 = (qw2 & 0x0000FFFF0000FFFF) \
			| ((qw2 & 0x3333000033330000) << 2) \
			| ((qw2 >> 2) & 0x3333000033330000); \
		qw3 = (qw3 & 0x0000FFFF0000FFFF) \
			| ((qw3 & 0x3333000033330000) << 2) \
			| ((qw3 >> 2) & 0x3333000033330000); \
		qw4 = ((qw4 & 0x0000111100001111) << 3) \
			| ((qw4 >> 1) & 0x0000777700007777) \
			| ((qw4 & 0x7777000077770000) << 1) \
			| ((qw4 >> 3) & 0x1111000011110000); \
		qw5 = ((qw5 & 0x0000111100001111) << 3) \
			| ((qw5 >> 1) & 0x0000777700007777) \
			| ((qw5 & 0x7777000077770000) << 1) \
			| ((qw5 >> 3) & 0x1111000011110000); \
		qw6 = ((qw6 & 0x0000111100001111) << 3) \
			| ((qw6 >> 1) & 0x0000777700007777) \
			| ((qw6 & 0x7777000077770000) << 1) \
			| ((qw6 >> 3) & 0x1111000011110000); \
		qw7 = ((qw7 & 0x0000111100001111) << 3) \
			| ((qw7 >> 1) & 0x0000777700007777) \
			| ((qw7 & 0x7777000077770000) << 1) \
			| ((qw7 >> 3) & 0x1111000011110000); \
	} while (0)

#define SR_SHEET   do { \
		qw0 = (qw0 & 0x0000FFFF0000FFFF) \
			| ((qw0 & 0x00FF000000FF0000) << 8) \
			| ((qw0 >> 8) & 0x00FF000000FF0000); \
		qw1 = (qw1 & 0x0000FFFF0000FFFF) \
			| ((qw1 & 0x00FF000000FF0000) << 8) \
			| ((qw1 >> 8) & 0x00FF000000FF0000); \
		qw2 = (qw2 & 0x0000FFFF0000FFFF) \
			| ((qw2 & 0x00FF000000FF0000) << 8) \
			| ((qw2 >> 8) & 0x00FF000000FF0000); \
		qw3 = (qw3 & 0x0000FFFF0000FFFF) \
			| ((qw3 & 0x00FF000000FF0000) << 8) \
			| ((qw3 >> 8) & 0x00FF000000FF0000); \
		qw4 = ((qw4 & 0x00000FFF00000FFF) << 4) \
			| ((qw4 >> 12) & 0x0000000F0000000F) \
			| ((qw4 & 0x000F0000000F0000) << 12) \
			| ((qw4 >> 4) & 0x0FFF00000FFF0000); \
		qw5 = ((qw5 & 0x00000FFF00000FFF) << 4) \
			| ((qw5 >> 12) & 0x0000000F0000000F) \
			| ((qw5 & 0x000F0000000F0000) << 12) \
			| ((qw5 >> 4) & 0x0FFF00000FFF0000); \
		qw6 = ((qw6 & 0x00000FFF00000FFF) << 4) \
			| ((qw6 >> 12) & 0x0000000F0000000F) \
			| ((qw6 & 0x000F0000000F0000) << 12) \
			| ((qw6 >> 4) & 0x0FFF00000FFF0000); \
		qw7 = ((qw7 & 0x00000FFF00000FFF) << 4) \
			| ((qw7 >> 12) & 0x0000000F0000000F) \
			| ((qw7 & 0x000F0000000F0000) << 12) \
			| ((qw7 >> 4) & 0x0FFF00000FFF0000); \
	} while (0)

#define SR_SHEET_INV   do { \
		qw0 = (qw0 & 0x0000FFFF0000FFFF) \
			| ((qw0 & 0x00FF000000FF0000) << 8) \
			| ((qw0 >> 8) & 0x00FF000000FF0000); \
		qw1 = (qw1 & 0x0000FFFF0000FFFF) \
			| ((qw1 & 0x00FF000000FF0000) << 8) \
			| ((qw1 >> 8) & 0x00FF000000FF0000); \
		qw2 = (qw2 & 0x0000FFFF0000FFFF) \
			| ((qw2 & 0x00FF000000FF0000) << 8) \
			| ((qw2 >> 8) & 0x00FF000000FF0000); \
		qw3 = (qw3 & 0x0000FFFF0000FFFF) \
			| ((qw3 & 0x00FF000000FF0000) << 8) \
			| ((qw3 >> 8) & 0x00FF000000FF0000); \
		qw4 = ((qw4 & 0x0000000F0000000F) << 12) \
			| ((qw4 >> 4) & 0x00000FFF00000FFF) \
			| ((qw4 & 0x0FFF00000FFF0000) << 4) \
			| ((qw4 >> 12) & 0x000F0000000F0000); \
		qw5 = ((qw5 & 0x0000000F0000000F) << 12) \
			| ((qw5 >> 4) & 0x00000FFF00000FFF) \
			| ((qw5 & 0x0FFF00000FFF0000) << 4) \
			| ((qw5 >> 12) & 0x000F0000000F0000); \
		qw6 = ((qw6 & 0x0000000F0000000F) << 12) \
			| ((qw6 >> 4) & 0x00000FFF00000FFF) \
			| ((qw6 & 0x0FFF00000FFF0000) << 4) \
			| ((qw6 >> 12) & 0x000F0000000F0000); \
		qw7 = ((qw7 & 0x0000000F0000000F) << 12) \
			| ((qw7 >> 4) & 0x00000FFF00000FFF) \
			| ((qw7 & 0x0FFF00000FFF0000) << 4) \
			| ((qw7 >> 12) & 0x000F0000000F0000); \
	} while (0)

#define XOR_KEY   do { \
		qw0 ^= keybuf[0]; \
		qw1 ^= keybuf[1]; \
		qw2 ^= keybuf[2]; \
		qw3 ^= keybuf[3]; \
		qw4 ^= keybuf[4]; \
		qw5 ^= keybuf[5]; \
		qw6 ^= keybuf[6]; \
		qw7 ^= keybuf[7]; \
	} while (0)

#define XOR_KEY_ROTATED   do { \
		qw0 ^= keybuf[ 8]; \
		qw1 ^= keybuf[ 9]; \
		qw2 ^= keybuf[10]; \
		qw3 ^= keybuf[11]; \
		qw4 ^= keybuf[12]; \
		qw5 ^= keybuf[13]; \
		qw6 ^= keybuf[14]; \
		qw7 ^= keybuf[15]; \
	} while (0)

/*
 * For Saturnin-CTR-Cascade: R = 10; D = 1, 2, 3, 4 or 5.
 */

static const uint64_t RC_10_2_bs64[] = {
	0x4E4526B54E4526B5, 0xA3565FF0A3565FF0, 0x0F8F20D80F8F20D8,
	0x0B54BEE10B54BEE1, 0x7D1A6C9D7D1A6C9D, 0x17A6280A17A6280A,
	0xAA46C986AA46C986, 0xC1199062C1199062, 0x182C5CDE182C5CDE,
	0xA00D53FEA00D53FE
};

static const uint64_t RC_10_3_bs64[] = {
	0x4E1626984E162698, 0xB2535BA1B2535BA1, 0x6C8F9D656C8F9D65,
	0x5816AD305816AD30, 0x691FD4FA691FD4FA, 0x6BF5BCF96BF5BCF9,
	0xF8EB3525F8EB3525, 0xB21DECFAB21DECFA, 0x7B3DA4177B3DA417,
	0xF62C94B4F62C94B4
};

static const uint64_t RC_10_combined_1_4_bs64[] = {
	0x4FAF265B4EB026C2, 0xC548461690595303, 0x45DCAD21AA8FE632,
	0xE08BD607FE928A92, 0x0504FDB84115A419, 0x1E1F525793539532,
	0x45FBC2165DB1CC4E, 0xEB529B1F541515CA, 0x52194E32BD1F55A8,
	0x5498C0185A6E1A0D
};

static const uint64_t RC_10_combined_1_5_bs64[] = {
	0x4FFC26764EB026C2, 0xD44D424790595303, 0x26DC109CAA8FE632,
	0xB3C9C5D6FE928A92, 0x110145DF4115A419, 0x624CC6A493539532,
	0x17563EB55DB1CC4E, 0x9856E787541515CA, 0x3108B6FBBD1F55A8,
	0x02B907525A6E1A0D
};

/*
 * Decode a key into 64-bit words (with bitslice-64 encoding, and
 * followed by the rotated key). The key is written only in the
 * low halves of the 64-bit words; the high halves are set to zero.
 */
static void
saturnin_bs64_key_expand_low(uint64_t *keybuf, const uint8_t *key)
{
	int i;

	for (i = 0; i < 8; i ++) {
		uint32_t w;

		w = (uint32_t)key[(i << 1) + 0]
			| ((uint32_t)key[(i << 1) + 1] << 8)
			| ((uint32_t)key[(i << 1) + 16] << 16)
			| ((uint32_t)key[(i << 1) + 17] << 24);
		keybuf[i] = (uint64_t)w;
		w = ((w & 0x001F001F) << 11)
			| ((w >> 5) & 0x07FF07FF);
		keybuf[i + 8] = (uint64_t)w;
	}
}

/*
 * Perform two parallel Saturnin block encryptions.
 *   R        number of super-rounds.
 *   rc       round constants (depends on R and D)
 *   keybuf   key and rotated key (16 words = 64 bytes)
 *   buf      blocks to encrypt
 * The encrypted block is written back in 'buf'.
 */
static void
saturnin_bs64_block_encrypt(int R, const uint64_t *rc,
	const uint64_t *keybuf, uint8_t *buf)
{
	DECL_STATE
	int i;

	/*
	 * Decode data into the registers.
	 */
	DEC512(buf);

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
		qw0 ^= rc[i + 0];
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
		qw0 ^= rc[i + 1];
		XOR_KEY;
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
do_cascade_aad(uint8_t *r, const uint64_t *keybuf,
	const uint8_t *nonce, const uint8_t *buf, size_t len)
{
	uint8_t tmp[64];
	uint64_t keybuf2[16];
	size_t u, v, clen;

	memcpy(tmp, nonce, 32);
	memset(tmp + 32, 0, 32);
	saturnin_bs64_block_encrypt(10, RC_10_2_bs64, keybuf, tmp);
	xor32(tmp, nonce);
	for (u = 0; (u + 31) < len; u += 32) {
		saturnin_bs64_key_expand_low(keybuf2, tmp);
		memcpy(tmp, buf + u, 32);
		saturnin_bs64_block_encrypt(10, RC_10_2_bs64, keybuf2, tmp);
		xor32(tmp, buf + u);
	}
	saturnin_bs64_key_expand_low(keybuf2, tmp);
	clen = len - u;
	if (clen > 0) {
		memcpy(tmp, buf + u, clen);
	}
	tmp[clen] = 0x80;
	memset(tmp + clen + 1, 0, 31 - clen);
	saturnin_bs64_block_encrypt(10, RC_10_3_bs64, keybuf2, tmp);
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
	uint64_t keybuf[16], keybuf2[16];
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
	saturnin_bs64_key_expand_low(keybuf, (const uint8_t *)k);

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
		saturnin_bs64_block_encrypt(10,
			RC_10_combined_1_4_bs64, keybuf, tmp);
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
			saturnin_bs64_key_expand_low(keybuf2, tmp + 32);
			for (i = 0; i < 16; i ++) {
				keybuf2[i] = (keybuf2[i] << 32) | keybuf[i];
			}
			memcpy(tmp + 32, buf + u - 32, 32);
			saturnin_bs64_block_encrypt(10,
				RC_10_combined_1_4_bs64, keybuf2, tmp);
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
		saturnin_bs64_key_expand_low(keybuf2, tmp + 32);
		for (i = 0; i < 16; i ++) {
			keybuf2[i] <<= 32;
		}
		memcpy(tmp + 32, tmp, 32);
		saturnin_bs64_block_encrypt(10,
			RC_10_combined_1_5_bs64, keybuf2, tmp);
		xor32(tag, tmp + 32);
	} else {
		memset(tmp + 32, 0, 32);
		memcpy(tmp, nonce, 32);
		tmp[31] = 0x01;
		saturnin_bs64_block_encrypt(10,
			RC_10_combined_1_4_bs64, keybuf, tmp);
		for (u = 0; u < len; u ++) {
			tmp[u] ^= buf[u];
		}
		memcpy(buf, tmp, len);
		tmp[len] = 0x80;
		memset(tmp + len + 1, 0, 31 - len);
		saturnin_bs64_key_expand_low(keybuf2, tag);
		for (i = 0; i < 16; i ++) {
			keybuf2[i] <<= 32;
		}
		memcpy(tag, tmp, 32);
		memcpy(tmp + 32, tmp, 32);
		saturnin_bs64_block_encrypt(10,
			RC_10_combined_1_5_bs64, keybuf2, tmp);
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
	uint64_t keybuf[16], keybuf2[16];
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
	saturnin_bs64_key_expand_low(keybuf, (const uint8_t *)k);

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
		saturnin_bs64_key_expand_low(keybuf2, tmp + 32);
		for (i = 0; i < 16; i ++) {
			keybuf2[i] = (keybuf2[i] << 32) | keybuf[i];
		}
		memcpy(tmp + 32, buf + u, 32);
		saturnin_bs64_block_encrypt(10,
			RC_10_combined_1_4_bs64, keybuf2, tmp);
		xor32(tmp + 32, buf + u);
		xor32(buf + u, tmp);
	}
	memcpy(tmp, nonce, 28);
	ctr = (u >> 5) + 1;
	tmp[28] = (uint8_t)(ctr >> 24);
	tmp[29] = (uint8_t)(ctr >> 16);
	tmp[30] = (uint8_t)(ctr >> 8);
	tmp[31] = (uint8_t)ctr;
	saturnin_bs64_key_expand_low(keybuf2, tmp + 32);
	for (i = 0; i < 16; i ++) {
		keybuf2[i] = (keybuf2[i] << 32) | keybuf[i];
	}
	rlen = len - u;
	if (rlen > 0) {
		memcpy(tmp + 32, buf + u, rlen);
	}
	tmp[32 + rlen] = 0x80;
	memset(tmp + 32 + rlen + 1, 0, 31 - rlen);
	memcpy(tag, tmp + 32, 32);
	saturnin_bs64_block_encrypt(10, RC_10_combined_1_5_bs64, keybuf2, tmp);
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
