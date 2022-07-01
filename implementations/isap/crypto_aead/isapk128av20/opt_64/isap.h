#ifndef ISAP_H
#define ISAP_H

// Rate in bits
#define ISAP_rH 144
#define ISAP_rB 1

// Number of rounds
#define ISAP_sH 16
#define ISAP_sB 1
#define ISAP_sE 8
#define ISAP_sK 8

// State size in bytes
#define ISAP_STATE_SZ 50

// Size of rate in bytes
#define ISAP_rH_SZ ((ISAP_rH+7)/8)

// Size of zero truncated IV in bytes
#define ISAP_IV_SZ 8

// Size of tag in bytes
#define ISAP_TAG_SZ 16

// Security level
#define ISAP_K 128

void isap_mac(
	const unsigned char *k,
	const unsigned char *npub,
	const unsigned char *ad, const unsigned long long adlen,
	const unsigned char *c, const unsigned long long clen,
	unsigned char *tag
);

void isap_rk(
	const unsigned char *k,
	const unsigned char *iv,
	const unsigned char *in,
	const unsigned long long inlen,
	unsigned char *out,
	const unsigned long long outlen
);

void isap_enc(
	const unsigned char *k,
	const unsigned char *npub,
	const unsigned char *m, const unsigned long long mlen,
	unsigned char *c
);

#endif
