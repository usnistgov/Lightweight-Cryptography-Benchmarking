#include "lwc_crypto_hash.h"
#include "api.h"


hash_ctx lwc_hash_ctx = {
	"asconxofv12",
	"armv6_lowsize",
	CRYPTO_BYTES,
	crypto_hash,
};

