#include "lwc_crypto_hash.h"
#include "api.h"
#include "orange.h"

hash_ctx lwc_hash_ctx = {
	"orangishv1",
	"ryhs",
	CRYPTO_BYTES,
	orangish_hash,
};

