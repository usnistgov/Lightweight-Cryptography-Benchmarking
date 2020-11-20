#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "crypto_aead.h"
#include "api.h"

#define ARR_SIZE(a) (sizeof((a))/sizeof((a[0])))

#define KNOT_CIPHER 1
#if defined(KNOT_CIPHER) && (KNOT_CIPHER == 1)
unsigned char constant6[63] = {
	0x01, 0x02, 0x04, 0x08, 0x10, 0x21, 0x03, 0x06,
	0x0c, 0x18,	0x31, 0x22, 0x05, 0x0a, 0x14, 0x29,
	0x13, 0x27, 0x0f, 0x1e, 0x3d, 0x3a,	0x34, 0x28,
	0x11, 0x23, 0x07, 0x0e, 0x1c, 0x39, 0x32, 0x24,
	0x09, 0x12,	0x25, 0x0b, 0x16, 0x2d, 0x1b, 0x37,
	0x2e, 0x1d, 0x3b, 0x36, 0x2c, 0x19,	0x33, 0x26,
	0x0d, 0x1a, 0x35, 0x2a, 0x15, 0x2b, 0x17, 0x2f,
	0x1f, 0x3f,	0x3e, 0x3c, 0x38, 0x30, 0x20 };

/* State
 * w4 w0
 * w5 w1
 * w6 w2
 * w7 w3
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
static void permutation256(unsigned char *in, int rounds, unsigned char *rc) {
	uint32_t w0, w1, w2, w3, w4, w5, w6, w7;
	uint32_t s0, s1, s2;
	uint32_t one = 0x1;
	uint32_t ff = 0xff;
	__asm volatile(
		"ldr     w0,     [in]          \n\t"
		"ldr     w4,     [in, #4]      \n\t"
		"ldr     w1,     [in, #8]      \n\t"
		"ldr     w5,     [in, #12]     \n\t"
		"ldr     w2,     [in, #16]     \n\t"
		"ldr     w6,     [in, #20]     \n\t"
		"ldr     w3,     [in, #24]     \n\t"
		"ldr     w7,     [in, #28]     \n\t"
		"mov     s0,     0xfff         \n\t"
		"mov     s2,     0x1fff        \n\t"
		"lsl     s2,     s2, #12       \n\t"
		"eors    s2,     s2, s0        \n\t"
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
    "/*rotate shift left 1 bit*/   \n\t"
		"ror     s0,     w1, #31       \n\t"
		"ands    s0,     s0, one       \n\t"
		"lsl     w1,     w1, #1        \n\t"
		"ror     s1,     w5, #31       \n\t"
		"ands    s1,     s1, one       \n\t"
		"eors    w1,     w1, s1        \n\t"
		"lsl     w5,     w5, #1        \n\t"
		"eors    w5,     w5, s0        \n\t"
    "/*rotate shift left 8 bits*/  \n\t"
		"ror     s0,     w2, #24       \n\t"
		"ands    s0,     s0, ff        \n\t"
		"lsl     w2,     w2, #8        \n\t"
		"ror     s1,     w6, #24       \n\t"
		"ands    s1,     s1, ff        \n\t"
		"eors    w2,     w2, s1        \n\t"
		"lsl     w6,     w6, #8        \n\t"
		"eors    w6,     w6, s0        \n\t"
    "/*rotate shift left 25 bits*/ \n\t"
		"ror     s0,     w3, #7        \n\t"
		"ands    s0,     s0, s2        \n\t"
		"lsl     w3,     w3, #25       \n\t"
		"ror     s1,     w7, #7        \n\t"
		"ands    s1,     s1, s2        \n\t"
		"eors    w3,     w3, s1        \n\t"
		"lsl     w7,     w7, #25       \n\t"
		"eors    w7,     w7, s0        \n\t"
		"/*loop control*/              \n\t"
 		"adds    rc,     rc, #1        \n\t"
		"subs    rounds, rounds,  #1   \n\t"
		"bne     enc_loop              \n\t"
		"str     w0,     [in]         \n\t"
		"str     w4,     [in, #4]     \n\t"
		"str     w1,     [in, #8]     \n\t"
		"str     w5,     [in, #12]    \n\t"
		"str     w2,     [in, #16]    \n\t"
		"str     w6,     [in, #20]    \n\t"
		"str     w3,     [in, #24]    \n\t"
		"str     w7,     [in, #28]    \n\t"
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
	unsigned int i;
	unsigned int last_index = 0;
	unsigned char *A = NULL;
	unsigned char *M = NULL;
	unsigned char S[32];
	unsigned int *A32 = NULL;
	unsigned int *M32 = NULL;
	unsigned int *S32 = NULL;
	unsigned int *C32 = NULL;

	// pad associated data
	if (adlen != 0) {
		u = (adlen + 8) >> 3;
		A = malloc(u << 3);
		if (A == NULL) {
			return -1;
		}
		memset(A, 0, u << 3);
		memcpy(A, ad, adlen);
		A[adlen] = 0x01;
		A32 = (unsigned int *)A;
	}

	// pad plaintext data
	if (mlen != 0) {
		v = (mlen + 8) >> 3;
		M = malloc(v << 3);
		if (M == NULL) {
			free(A);
			return -1;
		}
		memset(M, 0, v << 3);
		memcpy(M, m, mlen);
		M[mlen] = 0x01;
		M32 = (unsigned int *)M;
	}

	// initalization
	memcpy(S, npub, CRYPTO_NPUBBYTES);
	memcpy(S + CRYPTO_NPUBBYTES, k, CRYPTO_KEYBYTES);
	permutation256(S, 52, constant6);
	S32 = (unsigned int *)S;
 
	// processiong associated data
	if (adlen != 0) {
		for (i = 0; i < u; i++) {
			S32[0] ^= A32[0];
			S32[1] ^= A32[1];
			A32 = A32 + 2;
			permutation256(S, 28, constant6);
		}
	}
	S[31] ^= 0x80;

	// Encryption processiong plaintext data
	if (mlen != 0) {
		C32 = (unsigned int *)c;
		for (i = 0; i < v - 1; i++) {
			S32[0] ^= M32[0];
			S32[1] ^= M32[1];
			M32 = M32 + 2;
			C32[0] = S32[0];
			C32[1] = S32[1];
			C32 = C32 + 2;
			permutation256(S, 28, constant6);
		}
		v1 = mlen % 8;
		last_index = (v - 1) << 3;
		for (i = 0; i < v1; i++) {
			S[i] ^= M[last_index + i];
			c[last_index + i] = S[i];
		}
		S[i] ^= 0x01;
	}

	// finalization
	permutation256(S, 32, constant6);

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
	unsigned int u;
	unsigned int v = ((clen - CRYPTO_ABYTES) >> 3) + 1;
	unsigned int v1;
	unsigned int last_index;
	unsigned int i;
	unsigned char *A = NULL;
	unsigned char S[32];
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
		u = (adlen + 8) >> 3;
		A = malloc(u << 3);
		if (A == NULL) {
			return -1;
		}
		memset(A, 0, u << 3);
		memcpy(A, ad, adlen);
		A[adlen] = 0x01;
		A32 = (unsigned int *)A;
	}
	
	M32 = (unsigned int *)m;
	C32 = (unsigned int *)c;

	// initalization
	memcpy(S, npub, CRYPTO_NPUBBYTES);
	memcpy(S + CRYPTO_NPUBBYTES, k, CRYPTO_KEYBYTES);
	permutation256(S, 52, constant6);
	S32 = (unsigned int *)S;

	// processiong associated data
	if (adlen != 0) {
		for (i = 0; i < u; i++) {
			S32[0] ^= A32[0];
			S32[1] ^= A32[1];
			A32 = A32 + 2;
			permutation256(S, 28, constant6);
		}
	}
	S[31] ^= 0x80;

	// Encryption processiong 	ciphertext data
	if (clen != CRYPTO_ABYTES) {
		C32 = (unsigned int *)c;
		for (i = 0; i < v - 1; i++) {
			M32[0] = S32[0] ^ C32[0];
			M32[1] = S32[1] ^ C32[1];
			S32[0] = C32[0];
			S32[1] = C32[1];
			M32 = M32 + 2;
			C32 = C32 + 2;
			permutation256(S, 28, constant6);
		}
		v1 = (clen - CRYPTO_ABYTES) % 8;
		last_index = (v - 1) << 3;
		for (i = 0; i < v1; i++) {
			m[last_index + i] = S[i] ^ c[last_index + i];
			S[i] = c[last_index + i];
		}
		S[i] ^= 0x01;
	}

	// finalization
	permutation256(S, 32, constant6);

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

