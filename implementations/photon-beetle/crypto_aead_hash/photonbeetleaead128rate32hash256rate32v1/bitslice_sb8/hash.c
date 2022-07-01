#include "crypto_hash.h"

#include "beetle.h"
#include "photon.h"

/* Declaration of basic internal functions */
static uint8_t selectConst(
	const bool condition,
	const uint8_t option1,
	const uint8_t option2);

inline static void XOR_const(
	uint8_t *State_inout,
	const uint8_t  Constant);

/* Definition of basic internal functions */
static uint8_t selectConst(
	const bool condition,
	const uint8_t option1,
	const uint8_t option2)
{
	if (condition) return option1;
	return option2;
}

static void XOR_const(
	uint8_t *State_inout,
	const uint8_t  Constant)
{
	State_inout[STATE_INBYTES - 1] ^= (Constant << LAST_THREE_BITS_OFFSET);
}

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
	uint8_t State[STATE_INBYTES] = { 0 };

	uint8_t c0;

	if (inlen == 0)
	{
		XOR_const(State, 1);
	}
	else if (inlen <= HASH_INITIAL_RATE_INBYTES)
	{
		c0 = selectConst((inlen < HASH_INITIAL_RATE_INBYTES), 1, 2);
		memcpy(State, in, inlen);
		if (inlen < HASH_INITIAL_RATE_INBYTES) State[inlen] ^= 0x01; // ozs
		XOR_const(State, c0);
	}
	else
	{
		memcpy(State, in, HASH_INITIAL_RATE_INBYTES);
		inlen -= HASH_INITIAL_RATE_INBYTES;
		c0 = selectConst((inlen % HASH_RATE_INBYTES) == 0, 1, 2);
		HASH(State, in + HASH_INITIAL_RATE_INBYTES, inlen, c0, HASH_RATE_INBYTES);
	}
	TAG(out, State);
	out += SQUEEZE_RATE_INBYTES;
	TAG(out, State);

	return 0;
}