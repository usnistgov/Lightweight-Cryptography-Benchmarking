#include "lwc_crypto_hash.h"
#include "api.h"


hash_ctx lwc_hash_ctx = {
	"gimli24v1hash",
	"ref",
	CRYPTO_BYTES,
	crypto_hash,
};

