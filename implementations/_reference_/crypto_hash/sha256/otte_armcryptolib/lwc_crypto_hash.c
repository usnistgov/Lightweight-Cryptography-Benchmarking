#include "lwc_crypto_hash.h"
#include "api.h"
#include "sha256.h"

int crypto_hash(unsigned char* out, const unsigned char* in, unsigned long long inlen) {
	
	sha256(out, in, inlen * 8);
	return 0;
}

hash_ctx lwc_hash_ctx = {
	"sha256",
	"otte_armcryptolib",
	CRYPTO_BYTES,
	crypto_hash,
};

