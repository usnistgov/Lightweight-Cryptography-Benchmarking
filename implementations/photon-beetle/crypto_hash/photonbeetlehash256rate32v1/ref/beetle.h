
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include "api.h"

#define RATE_INBITS 32
#define RATE_INBYTES ((RATE_INBITS + 7) / 8)

#define INITIAL_RATE_INBITS 128
#define INITIAL_RATE_INBYTES ((INITIAL_RATE_INBITS + 7) / 8)

#define SQUEEZE_RATE_INBITS 128
#define SQUEEZE_RATE_INBYTES ((SQUEEZE_RATE_INBITS + 7) / 8)

#define CAPACITY_INBITS 224
#define CAPACITY_INBYTES ((CAPACITY_INBITS + 7) / 8)

#define STATE_INBITS (RATE_INBITS + CAPACITY_INBITS)
#define STATE_INBYTES ((STATE_INBITS + 7) / 8)

#define KEY_INBITS (CRYPTO_KEYBYTES * 8)
#define KEY_INBYTES (CRYPTO_KEYBYTES)

#define NOUNCE_INBITS (CRYPTO_NPUBBYTES * 8)
#define NOUNCE_INBYTES (CRYPTO_NPUBBYTES)

#define TAG_INBITS 256
#define TAG_INBYTES ((TAG_INBITS + 7) / 8)

#define LAST_THREE_BITS_OFFSET (STATE_INBITS - (STATE_INBYTES - 1) * 8 - 3)

#define TAG_MATCH	 0
#define TAG_UNMATCH	-1
#define OTHER_FAILURES -2

#define ENC 0
#define DEC 1