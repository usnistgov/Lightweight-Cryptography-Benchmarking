#include "lwc_crypto_hash.h"
#include "api.h"


hash_ctx lwc_hash_ctx = {
	"saturninhashv2",
	"bs32",
	CRYPTO_BYTES,
	crypto_hash,
};

