/* ======================================================================== */
/*
 * Saturnin-Short (NIST API).
 */

#include "crypto_aead.h"

#include <string.h>
#include <stdint.h>

void saturnin_block_encrypt(int R, int D, const uint8_t *key, uint8_t *buf);
void saturnin_block_decrypt(int R, int D, const uint8_t *key, uint8_t *buf);

/*
 * For the Short mode, we use 10 super-rounds, and the domain is 6.
 */
#define SATURNIN_SHORT_R   10
#define SATURNIN_SHORT_D    6

int
crypto_aead_encrypt(unsigned char *c, unsigned long long *clen,
	const unsigned char *m, unsigned long long mlen,
	const unsigned char *ad, unsigned long long adlen,
	const unsigned char *nsec,
	const unsigned char *npub,
	const unsigned char *k)
{
	uint8_t tmp[32];

	(void)ad;
	(void)nsec;

	/*
	 * Saturnin-Short does not support additional data.
	 */
	if (adlen != 0) {
		return -2;
	}

	/*
	 * Plaintext size MUST be less than 128 bits.
	 */
	if (mlen > 15) {
		return -2;
	}

	memcpy(tmp, npub, 16);
	if (mlen > 0) {
		memcpy(tmp + 16, m, mlen);
	}
	tmp[16 + mlen] = 0x80;
	memset(tmp + 16 + mlen + 1, 0x00, 15 - mlen);
	saturnin_block_encrypt(SATURNIN_SHORT_R, SATURNIN_SHORT_D,
		(const uint8_t *)k, tmp);
	memcpy(c, tmp, 32);
	*clen = 32;
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
	uint8_t tmp[32];
	unsigned tcc, notfound, u;
	int i;

	(void)ad;
	(void)nsec;

	/*
	 * Saturnin-Short does not support additional data.
	 */
	if (adlen != 0) {
		return -2;
	}

	/*
	 * Saturnin-Short ciphertext always has length exactly 32 bytes.
	 */
	if (clen != 32) {
		return -1;
	}

	memcpy(tmp, c, 32);
	saturnin_block_decrypt(SATURNIN_SHORT_R, SATURNIN_SHORT_D,
		(const uint8_t *)k, tmp);

	/*
	 * The first half of the block should be equal to the nonce
	 * (16 bytes), and the second half should be a valid padded
	 * plaintext. We perform a fully constant-time check of both
	 * properties, which is probably overkill.
	 */

	/*
	 * Compare the first half with the nonce. After this loop, tcc is
	 * zero if and only if the first half was equal to the nonce.
	 */
	tcc = 0;
	for (i = 0; i < 16; i ++) {
		tcc |= tmp[i] ^ npub[i];
	}

	/*
	 * Check and remove padding.
	 */
	notfound = 0xFF;
	u = 0;
	for (i = 15; i >= 0; i --) {
		unsigned b, f;

		b = tmp[16 + i];

		/*
		 * f is set to 0xFF if notfound is still 0xFF, and b == 0x80.
		 * Otherwise, f is zero.
		 */
		f = notfound & -(1 - (((b ^ 0x80) + 0xFF) >> 8));

		/*
		 * If f == 0xFF, then we found the message length.
		 */
		u |= f & (unsigned)i;

		/*
		 * We clear notfound if we found the 0x80 byte.
		 */
		notfound &= ~f;

		/*
		 * If notfound != 0, then we have not found the 0x80 byte
		 * yet, and the byte b should be 0x00. If this is not the
		 * case, then tcc is set to a non-zero value, which will
		 * trigger a failure.
		 */
		tcc |= notfound & ((b + 0xFF) >> 8);
	}
	tcc |= notfound;

	if (tcc != 0) {
		return -1;
	}
	memcpy(m, tmp + 16, u);
	*mlen = u;
	return 0;
}
