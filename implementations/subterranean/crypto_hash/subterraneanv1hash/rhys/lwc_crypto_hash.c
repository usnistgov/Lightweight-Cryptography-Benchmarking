#include "lwc_crypto_hash.h"
#include "api.h"
#include "subterranean.h"

hash_ctx lwc_hash_ctx = {
	"subterraneanv1hash",
	"rhys",
	CRYPTO_BYTES,
	subterranean_hash,
};

