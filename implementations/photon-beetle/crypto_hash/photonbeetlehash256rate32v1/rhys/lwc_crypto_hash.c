#include "lwc_crypto_hash.h"
#include "api.h"
#include "photon-beetle.h"

hash_ctx lwc_hash_ctx = {
	"photonbeetlehash256rate32v1",
	"rhys",
	CRYPTO_BYTES,
	photon_beetle_hash,
};

