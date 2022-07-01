#include "api.h"
#include "crypto_hash.h"
#include "Ascon-reference.h"

#define ASCON_128_RATE 8
#define ASCON_128_PA_ROUNDS 12
#define ASCON_128_STATE_SZ 40

const unsigned char ASCON_HASH_IV[] = {0x00,0x40,0x0c,0x00,0x00,0x00,0x01,0x00};

int crypto_hash(unsigned char* out, const unsigned char* in,
                unsigned long long len) {

  unsigned char state[ASCON_128_STATE_SZ];
	Ascon_Initialize(state);
  Ascon_AddBytes(state, ASCON_HASH_IV, 0, ASCON_128_RATE);
  Ascon_Permute_Nrounds(state,ASCON_128_PA_ROUNDS);

  /* absorb full plaintext blocks */
  while (len >= ASCON_128_RATE) {
    Ascon_AddBytes(state, in, 0, ASCON_128_RATE);
    Ascon_Permute_Nrounds(state,ASCON_128_PA_ROUNDS);
    in += ASCON_128_RATE;
    len -= ASCON_128_RATE;
  }
  /* absorb final plaintext block */
  Ascon_AddBytes(state, in, 0, len);

  /* absorb padding */
  unsigned char pad = 0x80;
	Ascon_AddBytes(state,&pad,len,1);
	Ascon_Permute_Nrounds(state,ASCON_128_PA_ROUNDS);

  /* squeeze full output blocks */
  len = CRYPTO_BYTES;
  while (len > ASCON_128_RATE) {
    Ascon_ExtractBytes(state, out, 0, ASCON_128_RATE);
    Ascon_Permute_Nrounds(state,ASCON_128_PA_ROUNDS);
    out += ASCON_128_RATE;
    len -= ASCON_128_RATE;
  }
  /* squeeze final output block */
  Ascon_ExtractBytes(state, out, 0, len);

  return 0;
}
