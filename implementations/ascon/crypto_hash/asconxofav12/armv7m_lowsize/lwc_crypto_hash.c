#include "lwc_crypto_hash.h"
#include "api.h"


hash_ctx lwc_hash_ctx = {
	"asconxofav12",
	"armv7m_lowsize",
	CRYPTO_BYTES,
	crypto_hash,
};

