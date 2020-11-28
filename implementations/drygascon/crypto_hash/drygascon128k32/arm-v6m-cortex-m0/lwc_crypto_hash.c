#include "lwc_crypto_hash.h"
#include "api.h"


hash_ctx lwc_hash_ctx = {
	"drygascon128hash",
	"arm-v6m-cortex-m0",
	CRYPTO_BYTES,
	crypto_hash,
};
