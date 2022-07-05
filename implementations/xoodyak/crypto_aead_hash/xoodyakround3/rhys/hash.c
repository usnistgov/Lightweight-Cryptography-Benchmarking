
#include "xoodyak-hash.h"

int crypto_hash
    (unsigned char *out, const unsigned char *in, unsigned long long inlen)
{
    return xoodyak_hash(out, in, inlen);
}
