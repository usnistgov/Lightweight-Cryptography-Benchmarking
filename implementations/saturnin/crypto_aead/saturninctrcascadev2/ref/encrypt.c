/* ======================================================================== */
/*
 * Saturnin-CTR-Cascade (NIST API).
 */

#include "crypto_aead.h"

#include <string.h>
#include <stdint.h>

void saturnin_block_encrypt(int R, int D, const uint8_t *key, uint8_t *buf);
void saturnin_block_decrypt(int R, int D, const uint8_t *key, uint8_t *buf);

/*
 * For CTR encryption, we use 10 super-rounds, and the domain is 1.
 */
#define SATURNIN_CTR_R   10
#define SATURNIN_CTR_D    1

/*
 * For the Cascade, we use 10 super-rounds. Domain is:
 *  - For the additional data: 2, except for the final block, which uses 3.
 *  - For the ciphertext: 4, except for the final block, which uses 5.
 */
#define SATURNIN_CASCADE_R        10
#define SATURNIN_CASCADE_D_AAD1    2
#define SATURNIN_CASCADE_D_AAD2    3
#define SATURNIN_CASCADE_D_CT1     4
#define SATURNIN_CASCADE_D_CT2     5

/*
 * Compute the initial state for the Cascade construction: input block
 * is the nonce with a counter value of 0.
 */
static void
do_cascade_init(uint8_t *r, const uint8_t *k, const uint8_t *nonce)
{
	size_t u;

	memcpy(r, nonce, 16);
	r[16] = 0x80;
	memset(r + 17, 0, 15);
	saturnin_block_encrypt(SATURNIN_CASCADE_R,
		SATURNIN_CASCADE_D_AAD1, k, r);
	for (u = 0; u < 16; u ++) {
		r[u] ^= nonce[u];
	}
	r[16] ^= 0x80;
}

/*
 * Compute the Cascade construction on some data (AAD or ciphertext),
 * using the provided domain parameters. For the AAD, the initial
 * state is assumed to be already initialized (with do_cascade_init()).
 * Padding is applied.
 */
static void
do_cascade(uint8_t *r, int D1, int D2, const uint8_t *buf, size_t len)
{
	size_t u;

	u = 0;
	for (;;) {
		size_t clen, v;
		int domain;
		uint8_t m[32], t[32];

		domain = D1;
		clen = len - u;
		if (clen >= sizeof t) {
			memcpy(t, buf + u, sizeof t);
			u += sizeof t;
		} else {
			memcpy(t, buf + u, clen);
			t[clen] = 0x80;
			memset(t + clen + 1, 0, (sizeof t) - clen - 1);
			domain = D2;
		}
		memcpy(m, t, sizeof t);
		saturnin_block_encrypt(SATURNIN_CASCADE_R, domain, r, m);
		for (v = 0; v < sizeof t; v ++) {
			r[v] = m[v] ^ t[v];
		}
		if (domain == D2) {
			break;
		}
	}
}

/*
 * Compute CTR encryption/decryption on data (in-place). This function
 * assumes that the number of blocks is less than 2^32-2.
 */
static void
do_ctr(const uint8_t *k, const uint8_t *nonce, uint8_t *buf, size_t len)
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
		size_t v, clen;

		memcpy(t, nonce, 16);
		t[16] = 0x80;
		memset(t + 17, 0, 11);
		t[28] = (uint8_t)(cc >> 24);
		t[29] = (uint8_t)(cc >> 16);
		t[30] = (uint8_t)(cc >> 8);
		t[31] = (uint8_t)cc;
		saturnin_block_encrypt(SATURNIN_CTR_R, SATURNIN_CTR_D, k, t);
		clen = len - u;
		if (clen > sizeof t) {
			clen = sizeof t;
		}
		for (v = 0; v < clen; v ++) {
			buf[u + v] ^= t[v];
		}
		cc ++;
		u += clen;
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
	uint8_t key[32], nonce[16];
	uint8_t tag[32];
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
	 * We copy the key and nonce into local buffer to avoid any
	 * overlap issue.
	 */
	(void)nsec;
	memcpy(key, k, sizeof key);
	memcpy(nonce, npub, sizeof nonce);

	/*
	 * Start the Cascade and process the AAD.
	 */
	do_cascade_init(tag, key, nonce);
	do_cascade(tag, SATURNIN_CASCADE_D_AAD1,
		SATURNIN_CASCADE_D_AAD2, (const uint8_t *)ad, (size_t)adlen);

	/*
	 * Encrypt the plaintext with CTR.
	 */
	memmove(c, m, len);
	do_ctr(key, nonce, c, len);

	/*
	 * Continue the Cascade on the ciphertext, and write the resulting
	 * tag at the end of the ciphertext.
	 */
	do_cascade(tag, SATURNIN_CASCADE_D_CT1,
		SATURNIN_CASCADE_D_CT2, (uint8_t *)c, len);
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
	uint8_t key[32], nonce[16];
	uint8_t tag[32];
	size_t len, u;
	unsigned tcc;

	/*
	 * In this implementation, we limit the plaintext length to less
	 * than 2^32-3 blocks (i.e. about 137.4 gigabytes), which allows
	 * us to keep the block counter on a single 32-bit integer.
	 */
	if ((clen >> 5) >= 0xFFFFFFFE) {
		return -2;
	}
	len = (size_t)clen;

	/*
	 * Check that there is enough room for the tag, and compute the
	 * plaintext length.
	 */
	if (len < sizeof tag) {
		return -1;
	}
	len -= sizeof tag;

	/*
	 * We copy the key and nonce into local buffer to avoid any
	 * overlap issue.
	 */
	(void)nsec;
	memcpy(key, k, sizeof key);
	memcpy(nonce, npub, sizeof nonce);

	/*
	 * Start the Cascade and process the AAD and the ciphertext.
	 */
	do_cascade_init(tag, key, nonce);
	do_cascade(tag, SATURNIN_CASCADE_D_AAD1,
		SATURNIN_CASCADE_D_AAD2, (const uint8_t *)ad, (size_t)adlen);
	do_cascade(tag, SATURNIN_CASCADE_D_CT1,
		SATURNIN_CASCADE_D_CT2, (uint8_t *)c, len);

	/*
	 * Compare the computed tag with the provided one. We do a
	 * constant-time comparison. Final value of tcc is 0 if the tags
	 * match, 1 otherwise.
	 */
	tcc = 0;
	for (u = 0; u < sizeof tag; u ++) {
		tcc |= tag[u] ^ c[len + u];
	}
	tcc = (tcc + 0xFF) >> 8;

	/*
	 * Decrypt the plaintext with CTR.
	 */
	memmove(m, c, len);
	do_ctr(key, nonce, m, len);
	*mlen = len;

	/*
	 * Returned value is 0 on success, -1 on error (tag mismatch).
	 */
	return -(int)tcc;
}
