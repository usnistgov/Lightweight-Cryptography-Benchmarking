#include "lwc_crypto_hash.h"
#include "api.h"
#include "sparkle_opt.h"

hash_ctx lwc_hash_ctx = {
	"esch256v2",
	"add_armv7m_small",
	CRYPTO_BYTES,
	crypto_hash,
};

