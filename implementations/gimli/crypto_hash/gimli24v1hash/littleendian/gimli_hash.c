#include <stdint.h>
#include <string.h>
#include "crypto_hash.h"

#include "gimli.inc"

int crypto_hash(unsigned char *out,const unsigned char *in,unsigned long long inlen)
{
  uint32_t state[12];
  uint8_t* state_8 = (uint8_t*)state;
  uint64_t i;

  memset(state,0,sizeof(state));

  while (inlen >= 16) {
    for(i=0;i<16;++i) state_8[i] ^= in[i];
    in += 16;
    inlen -= 16;
    gimli(state);
  }

  for (i=0;i<inlen;++i) state_8[i] ^= in[i];
  state_8[i] ^= 1;
  state_8[48-1] ^= 1;
  gimli(state);

  memcpy(out,state,16);
  gimli(state);
  memcpy(out+16,state,16);

  return 0;
}
