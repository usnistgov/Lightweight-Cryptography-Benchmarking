#include "lwc_crypto_hash.h"
#include "api.h"


hash_ctx lwc_hash_ctx = {
	"subterraneanv1hash",
	"add_mem_compact",
	CRYPTO_BYTES,
	crypto_hash,
};

