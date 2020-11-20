#include "lwc_crypto_hash.h"
#include "api.h"
#include "skinny-hash.h"

hash_ctx lwc_hash_ctx = {
	"skinnyhashtk2",
	"ryhs",
	CRYPTO_BYTES,
	skinny_tk2_hash,
};

