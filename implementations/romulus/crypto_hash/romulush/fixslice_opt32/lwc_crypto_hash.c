#include "lwc_crypto_hash.h"
#include "api.h"


hash_ctx lwc_hash_ctx = {
	"romulush",
	"fixslice_opt32",
	CRYPTO_BYTES,
	crypto_hash,
};

