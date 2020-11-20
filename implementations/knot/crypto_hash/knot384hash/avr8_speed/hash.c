#include <avr/io.h>
#include <avr/sfr_defs.h>
#include <stdlib.h>
#include <string.h>
#include "api.h"
#include "crypto_hash.h"

extern void crypto_hash_asm(
    unsigned char *out,
    const unsigned char *in,
    unsigned char inlen
    );

int crypto_hash(
	unsigned char *out,
	const unsigned char *in,
	unsigned long long inlen
)
{
	/*
	...
	... the code for the hash function implementation goes here
	... generating a hash value out[0],out[1],...,out[CRYPTO_BYTES-1]
	... from a message in[0],in[1],...,in[in-1] 
	...
	... return 0;
	*/

    crypto_hash_asm(out, in, inlen);

	return 0;
}