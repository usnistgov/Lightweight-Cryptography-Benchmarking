#include "lwc_crypto_hash.h"
#include "api.h"
#include "ace.h"

hash_ctx lwc_hash_ctx = {
	"acehash256v1",
	"rhys",
	CRYPTO_BYTES,
	ace_hash,
};

