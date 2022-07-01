#ifndef ISAP_H
#define ISAP_H

#include <inttypes.h>

// Rate in bits
#define ISAP_rH 64
#define ISAP_rB 1

// Number of rounds
#define ISAP_sH 12
#define ISAP_sB 1
#define ISAP_sE 6
#define ISAP_sK 12

// State size in bytes
#define ISAP_STATE_SZ 40

// Size of rate in bytes
#define ISAP_rH_SZ ((ISAP_rH + 7) / 8)

// Size of zero truncated IV in bytes
#define ISAP_IV_SZ 8

// Size of tag in bytes
#define ISAP_TAG_SZ 16

// Security level
#define ISAP_K 128

void isap_mac(
	const uint8_t *k,
	const uint8_t *npub,
	const uint8_t *ad, const uint64_t adlen,
	const uint8_t *c, const uint64_t clen,
	uint8_t *tag);

void isap_enc(
	const uint8_t *k,
	const uint8_t *npub,
	const uint8_t *m, const uint64_t mlen,
	uint8_t *c);

#endif
