/* ======================================================================== */
/*
 * Saturnin-Hash (NIST API).
 */

#include "crypto_hash.h"

#include <string.h>
#include <stdint.h>

void saturnin_block_encrypt(int R, int D, const uint8_t *key, uint8_t *buf);
void saturnin_block_decrypt(int R, int D, const uint8_t *key, uint8_t *buf);

#define SATURNIN_HASH_R    16
#define SATURNIN_HASH_D1    7
#define SATURNIN_HASH_D2    8

int
crypto_hash(unsigned char *out,
	const unsigned char *in, unsigned long long inlen)
{
	uint8_t r[32];
	size_t u, len;

	/*
	 * Input is padded with a bit of value 1 (i.e. a byte of value
	 * 0x80), then the minimum number of bits of value 0 to reach a
	 * length which is a multiple of the block size (256 bits = 32
	 * bytes). A running state r (256 bits) is maintained;
	 * processing of each input block m computes the new value of r
	 * as the XOR of m and Saturnin(r,m) (i.e. encryption of m with
	 * the old r as key). There are 16 super-rounds. The domain is
	 * 7, except for the processing of the last block (the one that
	 * contains the padding bit of value 1) for which the domain is
	 * 8.
	 */
	len = (size_t)inlen;
	memset(r, 0, sizeof r);
	u = 0;
	for (;;) {
		size_t clen, v;
		int domain;
		uint8_t m[32], t[32];

		domain = SATURNIN_HASH_D1;
		clen = len - u;
		if (clen >= sizeof t) {
			memcpy(t, in + u, sizeof t);
			u += sizeof t;
		} else {
			memcpy(t, in + u, clen);
			t[clen] = 0x80;
			memset(t + clen + 1, 0, (sizeof t) - clen - 1);
			domain = SATURNIN_HASH_D2;
		}
		memcpy(m, t, sizeof t);
		saturnin_block_encrypt(SATURNIN_HASH_R, domain, r, m);
		for (v = 0; v < sizeof r; v ++) {
			r[v] = m[v] ^ t[v];
		}
		if (domain == SATURNIN_HASH_D2) {
			break;
		}
	}
	memcpy(out, r, sizeof r);
	return 0;
}
