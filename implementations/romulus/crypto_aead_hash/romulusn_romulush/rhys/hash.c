
#include "romulus-hash.h"

int crypto_hash
    (unsigned char *out, const unsigned char *in, unsigned long long inlen)
{
    return romulus_hash(out, in, inlen);
}
