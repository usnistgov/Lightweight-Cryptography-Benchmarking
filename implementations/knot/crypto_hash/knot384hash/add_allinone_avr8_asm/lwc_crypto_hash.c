#include "lwc_crypto_hash.h"
#include "api.h"


hash_ctx lwc_hash_ctx = {
	"knot384hash",
	"add_allinone_avr8_asm",
	CRYPTO_BYTES,
	crypto_hash,
};

