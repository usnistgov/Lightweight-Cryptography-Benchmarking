#include "lwc_crypto_hash.h"
#include "api.h"


hash_ctx lwc_hash_ctx = {
	"xoodyakv1hash",
	"XKCP-plain-ua",
	CRYPTO_BYTES,
	crypto_hash,
};

