
#include "ascon-hash.h"

int crypto_hash
    (unsigned char *out, const unsigned char *in, unsigned long long inlen)
{
    return ascon_hash(out, in, inlen);
}
