#include "lwc_crypto_hash.h"
#include "api.h"


hash_ctx lwc_hash_ctx = {
	"asconxofv12",
	"bi32_armv7m_small",
	CRYPTO_BYTES,
	crypto_hash,
};

