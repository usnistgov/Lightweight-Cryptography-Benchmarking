
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include "api.h"
#include "photon.h"

#define AEAD_RATE_INBITS (32)
#define AEAD_RATE_INBYTES ((AEAD_RATE_INBITS + 7) / 8)
#define HASH_RATE_INBITS 32
#define HASH_RATE_INBYTES ((HASH_RATE_INBITS + 7) / 8)
#define HASH_INITIAL_RATE_INBITS 128
#define HASH_INITIAL_RATE_INBYTES ((HASH_INITIAL_RATE_INBITS + 7) / 8)

#define SQUEEZE_RATE_INBITS (128)
#define SQUEEZE_RATE_INBYTES ((SQUEEZE_RATE_INBITS + 7) / 8)

#define STATE_INBITS (256)
#define STATE_INBYTES ((STATE_INBITS + 7) / 8)

#define KEY_INBITS (CRYPTO_KEYBYTES * 8)
#define KEY_INBYTES (CRYPTO_KEYBYTES)

#define NOUNCE_INBITS (CRYPTO_NPUBBYTES * 8)
#define NOUNCE_INBYTES (CRYPTO_NPUBBYTES)

#define LAST_THREE_BITS_OFFSET (STATE_INBITS - (STATE_INBYTES - 1) * 8 - 3)

#define TAG_MATCH	 0
#define TAG_UNMATCH	-1
#define OTHER_FAILURES -2

#define ENC 0
#define DEC 1

void XOR(
	uint8_t *out,
	const uint8_t *in_left,
	const uint8_t *in_right,
	const size_t iolen_inbytes);


void HASH(
	uint8_t *State_inout,
	const uint8_t *Data_in,
	const uint64_t Dlen_inbytes,
	const uint8_t  Constant,
	const uint8_t  Rate_inbytes
	);

void TAG(
	uint8_t *Tag_out,
	uint8_t *State);
