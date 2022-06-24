#include "lwc_crypto_hash.h"
#include "api.h"


hash_ctx lwc_hash_ctx = {
	"asconhashv12",
	"opt32_lowsize",
	CRYPTO_BYTES,
	crypto_hash,
};

