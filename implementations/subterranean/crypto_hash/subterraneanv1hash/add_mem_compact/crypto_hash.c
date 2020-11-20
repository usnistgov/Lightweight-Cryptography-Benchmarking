#include <stdio.h>
#include <stdlib.h>
#include "subterranean_mem_compact.h"
#include "api.h"

int crypto_hash(unsigned char *out, const unsigned char *in, unsigned long long inlen){
    /* Call hash function */
    subterranean_xof_direct(out, CRYPTO_BYTES, in, inlen);
    /* Release memory */
    return 0;
}