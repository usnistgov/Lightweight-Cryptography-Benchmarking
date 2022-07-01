#include "lwc_crypto_hash.h"
#include "api.h"


hash_ctx lwc_hash_ctx = {
	"romulush",
	"arm_asm_fixslice_cortexm",
	CRYPTO_BYTES,
	crypto_hash,
};

