#include "lwc_crypto_hash.h"
#include "api.h"
#include "xoodyak.h"

hash_ctx lwc_hash_ctx = {
	"xoodyakv1hash",
	"rhys",
	CRYPTO_BYTES,
	xoodyak_hash,
};

