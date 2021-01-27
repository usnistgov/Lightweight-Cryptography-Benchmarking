#include "lwc_crypto_hash.h"
#include "api.h"
#include "ascon128.h"

hash_ctx lwc_hash_ctx = {
	"asconxofv12",
	"rhys",
	CRYPTO_BYTES,
	ascon_xof,
};

