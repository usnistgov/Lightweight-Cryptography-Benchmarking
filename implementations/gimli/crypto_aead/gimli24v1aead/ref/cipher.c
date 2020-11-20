#include <stdint.h>
#include <string.h>
#include "crypto_aead.h"

#include "gimli.inc"

int crypto_aead_encrypt(
  unsigned char *c,unsigned long long *clen,
  const unsigned char *m,unsigned long long mlen,
  const unsigned char *ad,unsigned long long adlen,
  const unsigned char *nsec,
  const unsigned char *npub,
  const unsigned char *k
)
{
  uint8_t state[48];
  unsigned long long i;

  memcpy(state,npub,16);
  memcpy(state+16,k,32);
  gimli(state);
  *clen = mlen + 16;

  while (adlen >= 16) {
    for (i = 0;i < 16;++i) state[i] ^= ad[i];
    gimli(state);
    ad += 16;
    adlen -= 16;
  }

  for (i = 0;i < adlen;++i) state[i] ^= ad[i];
  state[adlen] ^= 1;
  state[47] ^= 1;
  gimli(state);

  while (mlen >= 16) {
    for (i = 0;i < 16;++i) c[i] = state[i] ^= m[i];
    gimli(state);
    c += 16;
    m += 16;
    mlen -= 16;
  }

  for (i = 0;i < mlen;++i) c[i] = state[i] ^= m[i];
  c += mlen;
  state[mlen] ^= 1;
  state[47] ^= 1;
  gimli(state);

  for (i = 0;i < 16;++i) c[i] = state[i];

  return 0;
}

int crypto_aead_decrypt(
  unsigned char *m,unsigned long long *mlen,
  unsigned char *nsec,
  const unsigned char *c,unsigned long long clen,
  const unsigned char *ad,unsigned long long adlen,
  const unsigned char *npub,
  const unsigned char *k
)
{
  uint8_t state[48];
  uint32_t result;
  unsigned long long i;
  unsigned long long tlen;

  if (clen < 16) return -1;
  *mlen = tlen = clen - 16;

  memcpy(state,npub,16);
  memcpy(state+16,k,32);
  gimli(state);

  while (adlen >= 16) {
    for (i = 0;i < 16;++i) state[i] ^= ad[i];
    gimli(state);
    ad += 16;
    adlen -= 16;
  }

  for (i = 0;i < adlen;++i) state[i] ^= ad[i];
  state[adlen] ^= 1;
  state[47] ^= 1;
  gimli(state);

  while (tlen >= 16) {
    for (i = 0;i < 16;++i) m[i] = state[i] ^ c[i];
    for (i = 0;i < 16;++i) state[i] = c[i];
    gimli(state);
    c += 16;
    m += 16;
    tlen -= 16;
  }

  for (i = 0;i < tlen;++i) m[i] = state[i] ^ c[i];
  for (i = 0;i < tlen;++i) state[i] = c[i];
  c += tlen;
  m += tlen;
  state[tlen] ^= 1;
  state[47] ^= 1;
  gimli(state);

  result = 0;
  for (i = 0;i < 16;++i) result |= c[i] ^ state[i];
  result -= 1;
  result = ((int32_t) result) >> 16;

  tlen = *mlen;
  m -= tlen;
  for (i = 0;i < tlen;++i) m[i] &= result;

  return ~result;
}
