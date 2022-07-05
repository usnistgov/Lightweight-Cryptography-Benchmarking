#include "lwc_crypto_hash.h"
#include "api.h"
#include "xoodyak.h"

hash_ctx lwc_hash_ctx = {
	"xoodyakround3",
	"ref",
	CRYPTO_BYTES,
	crypto_hash,
};

