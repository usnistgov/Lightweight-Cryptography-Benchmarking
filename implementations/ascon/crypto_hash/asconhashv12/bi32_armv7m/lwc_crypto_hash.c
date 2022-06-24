#include "lwc_crypto_hash.h"
#include "api.h"


hash_ctx lwc_hash_ctx = {
	"asconhashv12",
	"bi32_armv7m",
	CRYPTO_BYTES,
	crypto_hash,
};

