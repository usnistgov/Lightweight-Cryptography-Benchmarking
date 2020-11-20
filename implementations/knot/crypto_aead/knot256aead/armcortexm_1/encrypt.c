#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "crypto_aead.h"
#include "api.h"

#define ARR_SIZE(a) (sizeof((a))/sizeof((a[0])))

#define KNOT_CIPHER 1
#if defined(KNOT_CIPHER) && (KNOT_CIPHER == 1)
unsigned char constant7[127] = {
		0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x41, 0x03, 0x06,
		0x0c, 0x18, 0x30, 0x61, 0x42, 0x05, 0x0a, 0x14, 0x28, 0x51, 0x23, 0x47,
		0x0f, 0x1e, 0x3c, 0x79, 0x72, 0x64, 0x48, 0x11, 0x22, 0x45, 0x0b, 0x16,
		0x2c, 0x59, 0x33, 0x67, 0x4e, 0x1d, 0x3a, 0x75, 0x6a, 0x54, 0x29, 0x53,
		0x27, 0x4f, 0x1f, 0x3e, 0x7d, 0x7a, 0x74, 0x68, 0x50, 0x21, 0x43, 0x07,
		0x0e, 0x1c, 0x38, 0x71, 0x62, 0x44, 0x09, 0x12, 0x24, 0x49, 0x13, 0x26,
		0x4d, 0x1b, 0x36, 0x6d, 0x5a, 0x35, 0x6b, 0x56, 0x2d, 0x5b, 0x37, 0x6f,
		0x5e, 0x3d, 0x7b, 0x76, 0x6c, 0x58, 0x31, 0x63, 0x46, 0x0d, 0x1a, 0x34,
		0x69, 0x52, 0x25, 0x4b, 0x17, 0x2e, 0x5d, 0x3b, 0x77, 0x6e, 0x5c, 0x39,
		0x73, 0x66, 0x4c, 0x19, 0x32, 0x65, 0x4a, 0x15, 0x2a, 0x55, 0x2b, 0x57,
		0x2f, 0x5f, 0x3f, 0x7f, 0x7e, 0x7c, 0x78, 0x70, 0x60, 0x40 };

#define load64(x1, x0, in)               \
    "ldr     x0,     [in]          \n\t" \
		"ldr     x1,     [in, #4]      \n\t"

#define store64(x1, x0, out)             \
		"str     x0,     [out]         \n\t" \
		"str     x1,     [out, #4]     \n\t"

/* State
 * w12 w8  w4  w0
 * w13 w9  w5  w1
 * w14 w10 w6  w2
 * w15 w11 w7  w3
 *
 * Sbox
	t1  = ~a;
	t2  = b  & t1;
	t3  = c  ^ t2; 
	h   = d  ^ t3; 
	t5  = b  | c; 
	t6  = d  ^ t1; 
	g   = t5 ^ t6; 
	t8  = b  ^ d; 
	t9  = t3 & t6; 
	e   = t8 ^ t9; 
	t11 = g  & t8; 
	f   = t3 ^ t11;
 *
 * Sbox after change
	a  = ~a; 
	s0  = b  & a;
	s0  = c  ^ s0;
	c  = b  | c; 
	a  = d  ^ a; 
	c   = c ^ a; 
	s1  = b  ^ d; 
	d   = d  ^ s0;
	a  = s0 & a; 
	a   = s1 ^ a; 
	b = c  & s1; 
	b   = s0 ^ b;
 */
static void permutation512(unsigned char *in, int rounds, unsigned char *rc) {
	uint32_t w0, w1, w2, w3, w4, w5, w6, w7;
	uint32_t w8, w9, w10, w11, w12, w13, w14, w15;
	uint32_t s0, s1;
	uint32_t one = 0x1;
	uint32_t ffff = 0xffff;
	uint32_t value;
	__asm volatile(
		"ldr     w0,     [in]          \n\t"
		"ldr     w4,     [in, #4]      \n\t"
		"ldr     w8,     [in, #8]      \n\t"
		"ldr     w12,    [in, #12]     \n\t"
		"ldr     w1,     [in, #16]     \n\t"
		"ldr     w5,     [in, #20]     \n\t"
		"ldr     w9,     [in, #24]     \n\t"
		"ldr     w13,    [in, #28]     \n\t"
		"ldr     w2,     [in, #32]     \n\t"
		"ldr     w6,     [in, #36]     \n\t"
		"ldr     w10,    [in, #40]     \n\t"
		"ldr     w14,    [in, #44]     \n\t"
		"ldr     w3,     [in, #48]     \n\t"
		"ldr     w7,     [in, #52]     \n\t"
		"ldr     w11,    [in, #56]     \n\t"
		"ldr     w15,    [in, #60]     \n\t"
		"mov     s0,     0xfff         \n\t"
		"mov     value,  0x1fff        \n\t"
		"lsl     value,  value, #12    \n\t"
		"eors    value,  value, s0     \n\t"
	"enc_loop:                       \n\t"
    "/*add round const*/           \n\t"
		"ldrb    s0,     [rc]          \n\t"
	  "eors    w0,     w0, s0        \n\t"
    "/*sbox first column*/         \n\t"
		"mvns    w0,     w0            \n\t"
		"ands    s0,     w1, w0        \n\t"
		"eors    s0,     w2, s0        \n\t"
		"orrs    w2,     w1, w2        \n\t"
		"eors    w0,     w3, w0        \n\t"
		"eors    w2,     w2, w0        \n\t"
		"eors    s1,     w1, w3        \n\t"
		"eors    w3,     w3, s0        \n\t"
		"ands    w0,     s0, w0        \n\t"
		"eors    w0,     s1, w0        \n\t"
		"ands    w1,     w2, s1        \n\t"
		"eors    w1,     s0, w1        \n\t"
		"/*sbox second column*/        \n\t"
		"mvns    w4,     w4            \n\t"
		"ands    s0,     w5, w4        \n\t"
		"eors    s0,     w6, s0        \n\t"
		"orrs    w6,     w5, w6        \n\t"
		"eors    w4,     w7, w4        \n\t"
		"eors    w6,     w6, w4        \n\t"
		"eors    s1,     w5, w7        \n\t"
		"eors    w7,     w7, s0        \n\t"
		"ands    w4,     s0, w4        \n\t"
		"eors    w4,     s1, w4        \n\t"
		"ands    w5,     w6, s1        \n\t"
		"eors    w5,     s0, w5        \n\t"
		"/*sbox third column*/         \n\t"
		"mvns    w8,     w8            \n\t"
		"ands    s0,     w9,  w8       \n\t"
		"eors    s0,     w10, s0       \n\t"
		"orrs    w10,    w9,  w10      \n\t"
		"eors    w8,     w11, w8       \n\t"
		"eors    w10,    w10, w8       \n\t"
		"eors    s1,     w9,  w11      \n\t"
		"eors    w11,    w11, s0       \n\t"
		"ands    w8,     s0,  w8       \n\t"
		"eors    w8,     s1,  w8       \n\t"
		"ands    w9,     w10, s1       \n\t"
		"eors    w9,     s0,  w9       \n\t"
		"/*sbox forth column*/         \n\t"
		"mvns    w12,    w12           \n\t"
		"ands    s0,     w13, w12      \n\t"
		"eors    s0,     w14, s0       \n\t"
		"orrs    w14,    w13, w14      \n\t"
		"eors    w12,    w15, w12      \n\t"
		"eors    w14,    w14, w12      \n\t"
		"eors    s1,     w13, w15      \n\t"
		"eors    w15,    w15, s0       \n\t"
		"ands    w12,    s0,  w12      \n\t"
		"eors    w12,    s1,  w12      \n\t"
		"ands    w13,    w14, s1       \n\t"
		"eors    w13,    s0,  w13      \n\t"
    "/*rotate shift left 1 bit*/   \n\t"
		"ror     s0,     w1, #31       \n\t"
		"ands    s0,     s0, one       \n\t"
		"lsl     w1,     w1, #1        \n\t"
		"ror     s1,     w13,#31       \n\t"
		"ands    s1,     s1, one       \n\t"
		"eors    w1,     w1, s1        \n\t"
		"ror     s1,     w9, #31       \n\t"
		"ands    s1,     s1, one       \n\t"
		"lsl     w13,    w13,#1        \n\t"
		"eors    w13,    w13,s1        \n\t"
		"ror     s1,     w5, #31       \n\t"
		"ands    s1,     s1, one       \n\t"
		"lsl     w9,     w9, #1        \n\t"
		"eors    w9,     w9, s1        \n\t"
		"lsl     w5,     w5, #1        \n\t"
		"eors    w5,     w5, s0        \n\t"
    "/*rotate shift left 16 bits*/ \n\t"
		"ror     s0,     w2, #16       \n\t"
		"ands    s0,     s0, ffff      \n\t"
		"lsl     w2,     w2, #16       \n\t"
		"ror     s1,     w14,#16       \n\t"
		"ands    s1,     s1, ffff      \n\t"
		"eors    w2,     w2, s1        \n\t"
		"ror     s1,     w10,#16       \n\t"
		"ands    s1,     s1, ffff      \n\t"
		"lsl     w14,    w14,#16       \n\t"
		"eors    w14,    w14,s1        \n\t"
		"ror     s1,     w6, #16       \n\t"
		"ands    s1,     s1, ffff      \n\t"
		"lsl     w10,    w10,#16       \n\t"
		"eors    w10,    w10,s1        \n\t"
		"lsl     w6,     w6, #16       \n\t"
		"eors    w6,     w6, s0        \n\t"
    "/*rotate shift left 25 bits*/ \n\t"
		"ror     s0,     w3, #7        \n\t"
		"ands    s0,     s0, value     \n\t"
		"lsl     w3,     w3, #25       \n\t"
		"ror     s1,     w15,#7        \n\t"
		"ands    s1,     s1, value     \n\t"
		"eors    w3,     w3, s1        \n\t"
		"ror     s1,     w11,#7        \n\t"
		"ands    s1,     s1, value     \n\t"
		"lsl     w15,    w15,#25       \n\t"
		"eors    w15,    w15,s1        \n\t"
		"ror     s1,     w7, #7        \n\t"
		"ands    s1,     s1, value     \n\t"
		"lsl     w11,    w11,#25       \n\t"
		"eors    w11,    w11,s1        \n\t"
		"lsl     w7,     w7, #25       \n\t"
		"eors    w7,     w7, s0        \n\t"
		"/*loop control*/              \n\t"
 		"adds    rc,     rc,  #1       \n\t"
		"subs    rounds, rounds, #1    \n\t"
		"bne     enc_loop              \n\t"
		"str     w0,     [in]          \n\t"
		"str     w4,     [in, #4]      \n\t"
		"str     w8,     [in, #8]      \n\t"
		"str     w12,    [in, #12]     \n\t"
		"str     w1,     [in, #16]     \n\t"
		"str     w5,     [in, #20]     \n\t"
		"str     w9,     [in, #24]     \n\t"
		"str     w13,    [in, #28]     \n\t"
		"str     w2,     [in, #32]     \n\t"
		"str     w6,     [in, #36]     \n\t"
		"str     w10,    [in, #40]     \n\t"
		"str     w14,    [in, #44]     \n\t"
		"str     w3,     [in, #48]     \n\t"
		"str     w7,     [in, #52]     \n\t"
		"str     w11,    [in, #56]     \n\t"
		"str     w15,    [in, #60]     \n\t"
	);
}

int crypto_aead_encrypt(unsigned char *c, unsigned long long *clen,
                        const unsigned char *m, unsigned long long mlen,
                        const unsigned char *ad, unsigned long long adlen,
                        const unsigned char *nsec, const unsigned char *npub,
                        const unsigned char *k) {
	unsigned int u = 0;
	unsigned int v = 0;
	unsigned int v1 = 0;
	unsigned int last_index = 0;
	unsigned int i;
	unsigned char *A = NULL;
	unsigned char *M = NULL;
	unsigned char S[64];
	unsigned int *A32 = NULL;
	unsigned int *M32 = NULL;
	unsigned int *S32 = NULL;
	unsigned int *C32 = NULL;

	// pad associated data
	if (adlen != 0) {
		u = adlen / 16 + 1;
		A = malloc(u * 16);
		if (A == NULL) {
			return -1;
		}
		memset(A, 0, u * 16);
		memcpy(A, ad, adlen);
		A[adlen] = 0x01;
		A32 = (unsigned int *)A;
	}

	// pad plaintext data
	if (mlen != 0) {
		v = mlen / 16 + 1;
		M = malloc(v * 16);
		if (M == NULL) {
			free(A);
			return -1;
		}
		memset(M, 0, v * 16);
		memcpy(M, m, mlen);
		M[mlen] = 0x01;
		M32 = (unsigned int *)M;
	}

	// initalization
	memcpy(S, npub, CRYPTO_NPUBBYTES);
	memcpy(S + CRYPTO_NPUBBYTES, k, CRYPTO_KEYBYTES);
	permutation512(S, 100, constant7);
	S32 = (unsigned int *)S;
 
	// processiong associated data
	if (adlen != 0) {
		for (i = 0; i < u; i++) {
			S32[0] ^= A32[0];
			S32[1] ^= A32[1];
			S32[2] ^= A32[2];
			S32[3] ^= A32[3];
			A32 = A32 + 4;
			permutation512(S, 52, constant7);
		}
	}
	S[63] ^= 0x80;

	// Encryption processiong plaintext data
	if (mlen != 0) {
		C32 = (unsigned int *)c;
		for (i = 0; i < v - 1; i++) {
			S32[0] ^= M32[0];
			S32[1] ^= M32[1];
			S32[2] ^= M32[2];
			S32[3] ^= M32[3];
			M32 = M32 + 4;
			C32[0] = S32[0];
			C32[1] = S32[1];
			C32[2] = S32[2];
			C32[3] = S32[3];
			C32 = C32 + 4;
			permutation512(S, 52, constant7);
		}
		v1 = mlen % 16;
		last_index = (v - 1) * 16;
		for (i = 0; i < v1; i++) {
			S[i] ^= M[last_index + i];
			c[last_index + i] = S[i];
		}
		S[i] ^= 0x01;
	}

	// finalization
	permutation512(S, 56, constant7);

	// return tag
	memcpy(c + mlen, S, CRYPTO_ABYTES);
	*clen = mlen + CRYPTO_ABYTES;
	if (A != NULL) {
		free(A);
	}
	if (M != NULL) {
		free(M);
	}
	return 0;
}

int crypto_aead_decrypt(unsigned char *m, unsigned long long *mlen,
                        unsigned char *nsec,
                        const unsigned char *c, unsigned long long clen,
                        const unsigned char *ad, unsigned long long adlen,
                        const unsigned char *npub, const unsigned char *k)
{
	unsigned int u = 0;
	unsigned int v = 0;
	unsigned int v1 = 0;
	unsigned int last_index = 0;
	unsigned int i;
	unsigned char *A = NULL;
	unsigned char S[64];
	unsigned int *A32 = NULL;
	unsigned int *M32 = NULL;
	unsigned int *S32 = NULL;
	unsigned int *C32 = NULL;

	*mlen = 0;
	if (clen < CRYPTO_ABYTES) {
		return -1;
	}

	// pad associated data
	if (adlen != 0) {
		u = adlen / 16 + 1;
		A = malloc(u * 16);
		if (A == NULL) {
			return -1;
		}
		memset(A, 0, u * 16);
		memcpy(A, ad, adlen);
		A[adlen] = 0x01;
		A32 = (unsigned int *)A;
	}
	
	M32 = (unsigned int *)m;
	C32 = (unsigned int *)c;

	// initalization
	memcpy(S, npub, CRYPTO_NPUBBYTES);
	memcpy(S + CRYPTO_NPUBBYTES, k, CRYPTO_KEYBYTES);
	permutation512(S, 100, constant7);
	S32 = (unsigned int *)S;

	// processiong associated data
	if (adlen != 0) {
		for (i = 0; i < u; i++) {
			S32[0] ^= A32[0];
			S32[1] ^= A32[1];
			S32[2] ^= A32[2];
			S32[3] ^= A32[3];
			A32 = A32 + 4;
			permutation512(S, 52, constant7);
		}
	}
	S[63] ^= 0x80;

	// Encryption processiong 	ciphertext data
	if (clen != CRYPTO_ABYTES) {
		C32 = (unsigned int *)c;
		v = (clen - CRYPTO_ABYTES) / 16 + 1;
		for (i = 0; i < v - 1; i++) {
			M32[0] = S32[0] ^ C32[0];
			M32[1] = S32[1] ^ C32[1];
			M32[2] = S32[2] ^ C32[2];
			M32[3] = S32[3] ^ C32[3];
			S32[0] = C32[0];
			S32[1] = C32[1];
			S32[2] = C32[2];
			S32[3] = C32[3];
			M32 = M32 + 4;
			C32 = C32 + 4;
			permutation512(S, 52, constant7);
		}
		v1 = (clen - CRYPTO_ABYTES) % 16;
		last_index = (v - 1) * 16;
		for (i = 0; i < v1; i++) {
			m[last_index + i] = S[i] ^ c[last_index + i];
			S[i] = c[last_index + i];
		}
		S[i] ^= 0x01;
	}

	// finalization
	permutation512(S, 56, constant7);

	// return -1 if verification fails
	for (i = 0; i < CRYPTO_ABYTES; i++) {
		if (c[clen - CRYPTO_ABYTES + i] != S[i]) {
			memset(m, 0, clen - CRYPTO_ABYTES);
			return -1;
		}
	}
	*mlen = clen - CRYPTO_ABYTES;
	if (A != NULL) {
		free(A);
	}
	return 0;
}
#else
int crypto_aead_encrypt(unsigned char *c, unsigned long long *clen,
                        const unsigned char *m, unsigned long long mlen,
												const unsigned char *ad, unsigned long long adlen,
												const unsigned char *nsec, const unsigned char *npub,
												const unsigned char *k) {
	return 0;
}
int crypto_aead_decrypt(unsigned char *m, unsigned long long *mlen,
                        unsigned char *nsec,
                        const unsigned char *c, unsigned long long clen,
                        const unsigned char *ad, unsigned long long adlen,
                        const unsigned char *npub, const unsigned char *k) {
	return 0;
}
#endif