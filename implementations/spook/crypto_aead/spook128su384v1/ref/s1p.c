/* Spook Reference Implementation v1
 *
 * Written in 2019 at UCLouvain (Belgium) by Olivier Bronchain, Gaetan Cassiers
 * and Charles Momin.
 * To the extent possible under law, the author(s) have dedicated all copyright
 * and related and neighboring rights to this software to the public domain
 * worldwide. This software is distributed without any warranty.
 *
 * You should have received a copy of the CC0 Public Domain Dedication along with
 * this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
 */
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "s1p.h"
#include "parameters.h"
#include "primitives.h"
#include "utils.h"

#define CAPACITY_BYTES 32
#define RATE_BYTES (SHADOW_NBYTES - CAPACITY_BYTES)

// Working mode for block compression.
typedef enum {
  AD,
  PLAINTEXT,
  CIPHERTEXT
} compress_mode;

static void compress_block(unsigned char *state, unsigned char *out,
                           const unsigned char *d, compress_mode mode,
                           unsigned long long offset, unsigned long long n);

static unsigned long long compress_data(unsigned char *state,
                                        unsigned char *out,
                                        const unsigned char *d,
                                        unsigned long long dlen,
                                        compress_mode mode);

static void init_sponge_state(unsigned char state[SHADOW_NBYTES],
                              const unsigned char *k, const unsigned char *p,
                              const unsigned char *n);

void init_keys(const unsigned char **k, unsigned char p[P_NBYTES],
               const unsigned char *k_glob) {
  *k = k_glob;
#if MULTI_USER
  memcpy(p, k_glob + CLYDE128_NBYTES, P_NBYTES);
  p[P_NBYTES - 1] &= 0x7F; // set last p bit to 0
  p[P_NBYTES - 1] |= 0x40; // set next to last p bit to 0
#else
  memset(p, 0, P_NBYTES);
#endif // MULTI_USER
}

static void init_sponge_state(unsigned char state[SHADOW_NBYTES],
                              const unsigned char *k, const unsigned char *p,
                              const unsigned char *n) {
  // init state
  memset(state, 0, SHADOW_NBYTES);
  memcpy(state, p, P_NBYTES);
  memcpy(state + P_NBYTES, n, CRYPTO_NPUBBYTES);
  // TBC
  unsigned char padded_nonce[CLYDE128_NBYTES] = { 0 };
  memcpy(padded_nonce, n, CRYPTO_NPUBBYTES);
  unsigned char *b = state + (SHADOW_NBYTES - CLYDE128_NBYTES);
  clyde128_encrypt(b, padded_nonce, p, k);
  // initial permutation
  shadow(state);
}

void s1p_encrypt(unsigned char *c, unsigned long long *clen,
                 const unsigned char *ad, unsigned long long adlen,
                 const unsigned char *m, unsigned long long mlen,
                 const unsigned char *k, const unsigned char *p,
                 const unsigned char *n) {
  // permutation state
  unsigned char state[SHADOW_NBYTES];
  init_sponge_state(state, k, p, n);

  // compress associated data
  compress_data(state, NULL, ad, adlen, AD);

  // compress message
  unsigned long long c_bytes = 0;
  if (mlen > 0) {
    state[RATE_BYTES] ^= 0x01;
    c_bytes = compress_data(state, c, m, mlen, PLAINTEXT);
  }

  // tag
  state[CLYDE128_NBYTES + CLYDE128_NBYTES - 1] |= 0x80;
  clyde128_encrypt(c + c_bytes, state, state + CLYDE128_NBYTES, k);
  *clen = c_bytes + CLYDE128_NBYTES;
}

int s1p_decrypt(unsigned char *m, unsigned long long *mlen,
                const unsigned char *ad, unsigned long long adlen,
                const unsigned char *c, unsigned long long clen,
                const unsigned char *k, const unsigned char *p,
                const unsigned char *n) {
  // permutation state
  unsigned char state[SHADOW_NBYTES];
  init_sponge_state(state, k, p, n);

  // compress associated data
  compress_data(state, NULL, ad, adlen, AD);

  // compress message
  unsigned long long m_bytes = 0;
  if (clen > CLYDE128_NBYTES) {
    state[RATE_BYTES] ^= 0x01;
    m_bytes = compress_data(state, m, c, clen - CLYDE128_NBYTES, CIPHERTEXT);
  }

  // tag
  unsigned char inv_tag[CLYDE128_NBYTES];
  unsigned char *u = state;
  state[(2 * CLYDE128_NBYTES) - 1] |= 0x80;
  clyde128_decrypt(inv_tag, c + m_bytes, state + CLYDE128_NBYTES, k);
  int tag_ok = 1;
  for (int i = 0; i < CLYDE128_NBYTES; i++) {
    tag_ok &= (u[i] == inv_tag[i]);
  }
  if (tag_ok) {
    *mlen = m_bytes;
    return 0;
  } else {
    // Reset output buffer to avoid unintended unauthenticated plaintext
    // release.
    memset(m, 0, clen - CLYDE128_NBYTES);
    *mlen = 0;
    return -1;
  }
}

// Compress a block into the state. Length of the block is n and buffers are
// accessed starting at offset.  Input block is d, output is written into
// buffer out if mode is PLAINTEXT or CIPHERTEXT.
// Only the XOR operation is performed, not XORing of padding constants.
static void compress_block(unsigned char *state, unsigned char *out,
                           const unsigned char *d, compress_mode mode,
                           unsigned long long offset, unsigned long long n) {
  if (mode == CIPHERTEXT) {
    xor_bytes(out + offset, state, d + offset, n);
    memcpy(state, d + offset, n);
  } else {
    xor_bytes(state, state, d + offset, n);
    if (mode == PLAINTEXT) {
      memcpy(out + offset, state, n);
    }
  }
}

// Compress a block into the state (in duplex-sponge mode).
// Input data buffer is d with length dlen.
// Output is written into buffer out if mode is PLAINTEXT or CIPHERTEXT.
// Padding is handled if needed.
static unsigned long long compress_data(unsigned char *state,
                                        unsigned char *out,
                                        const unsigned char *d,
                                        unsigned long long dlen,
                                        compress_mode mode) {
  unsigned long long i;
  for (i = 0; i < dlen / RATE_BYTES; i++) {
    compress_block(state, out, d, mode, i * RATE_BYTES, RATE_BYTES);
    shadow(state);
  }
  int rem = dlen % RATE_BYTES;
  if (rem != 0) {
    compress_block(state, out, d, mode, i * RATE_BYTES, rem);
    state[rem] ^= 0x01;
    state[RATE_BYTES] ^= 0x02;
    shadow(state);
  }
  return i * RATE_BYTES + rem;
}
