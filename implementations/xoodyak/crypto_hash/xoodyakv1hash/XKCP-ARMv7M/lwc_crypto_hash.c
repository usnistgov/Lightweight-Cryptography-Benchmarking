#include "lwc_crypto_hash.h"
#include "api.h"


hash_ctx lwc_hash_ctx = {
	"xoodyakv1hash",
	"XKCP-ARMv7M",
	CRYPTO_BYTES,
	crypto_hash,
};

