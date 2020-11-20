///////////////////////////////////////////////////////////////////////////////
// hash.c: Optimized C implementation of the hash function ESCH384.          //
// This file is part of the SPARKLE submission to NIST's LW Crypto Project.  //
// Version 1.0.0 (2019-03-29), see <http://www.cryptolux.org/> for updates.  //
// Authors: The SPARKLE Group (C. Beierle, A. Biryukov, L. Cardoso dos       //
// Santos, J. Groszschaedl, L. Perrin, A. Udovenko, V. Velichkov, Q. Wang).  //
// License: GPLv3 (see LICENSE file), other licenses available upon request. //
// Copyright (C) 2019 University of Luxembourg <http://www.uni.lu/>.         //
// ------------------------------------------------------------------------- //
// This program is free software: you can redistribute it and/or modify it   //
// under the terms of the GNU General Public License as published by the     //
// Free Software Foundation, either version 3 of the License, or (at your    //
// option) any later version. This program is distributed in the hope that   //
// it will be useful, but WITHOUT ANY WARRANTY; without even the implied     //
// warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the  //
// GNU General Public License for more details. You should have received a   //
// copy of the GNU General Public License along with this program. If not,   //
// see <http://www.gnu.org/licenses/>.                                       //
///////////////////////////////////////////////////////////////////////////////

// This source code file should be compiled with the following set of flags:
// -std=c99 -Wall -Wextra -Wshadow -fsanitize=address,undefined -O2

// gencat_hash.c shall be used to generate the test vector output file. The
// test vector output file shall be provided in the corresponding
// crypto_hash/[algorithm]/ directory

#include <string.h>
#include "api.h"
#include "crypto_hash.h"
#include "eschconfig.h"
#include "sparkle_opt.h"

// crypto_hash.h MUST NOT be modified in any way! The file should not be
// included in the reference implementation

typedef unsigned char uchar_t;
typedef unsigned long long int ullint_t;

static const uint32_t MASK16 = 0xFFFFU;

#define ROT(x, n) (((x) >> (n)) | ((x) << (32-(n))))
#define ELL(x) (ROT((x), 16) ^ ((x) & MASK16))


// The function injectm_opt adds a 16-byte block of the message to the two
// leftmost branches of the state (i.e. to the state-words x0, y0, x1, and y1),
// whereby the block is first transformed via a linear Feistel function.

void injectm_opt(uint32_t *state, const uint32_t *msgwords, int nb)
{
  int i;
  uint32_t tmpx = 0, tmpy = 0;

  // Since the message block is 16 bytes long, we need to consider only two
  // x-words when computing tmpx and two y-words when computing tmpy.

  for(i = 0; i < MSGBLOCK_WLEN; i += 2) {
    tmpx ^= msgwords[i];
    tmpy ^= msgwords[i+1];
  }
  tmpx = ELL(tmpx);
  tmpy = ELL(tmpy);

  // The two leftmost x-words of the state are updated by adding the two
  // x-words of the message and tmpy to them, and the same is done with the two
  // leftmost y-words. The remaining nb/2-2 x-words are updated by just adding
  // tmpy to them, and the same is done with the remaining nb/2-2 y-words.

  for(i = 0; i < MSGBLOCK_WLEN; i += 2) {
    state[i] ^= (msgwords[i] ^ tmpy);
    state[i+1] ^= (msgwords[i+1] ^ tmpx);
  }
  for(i = MSGBLOCK_WLEN; i < nb; i += 2) {
    state[i] ^= tmpy;
    state[i+1] ^= tmpx;
  }
}


// To ensure compatibility with the SUPERCOP, the below implementation of
// crypto_hash can handle overlapping input and output buffers.

int crypto_hash(uchar_t *out, const uchar_t *in, ullint_t inlen)
{
  uint32_t state[2*NUM_BRANCHES] = { 0 };   // We have two words in each branch
  uint32_t lastblk[MSGBLOCK_WLEN] = { 0 };  // Buffer for last block of message
  // The type size_t is large enough to contain the size in bytes of any object
  size_t in_blen = (size_t) inlen;

  // A message exceeding 16 bytes is absorbed in 16-byte blocks. Note that the
  // loop below is not iterated at all when inlen <= 16 bytes.

  while(in_blen > MSGBLOCK_BLEN) {
    // Add 16 bytes of the message to the state
    injectm_opt(state, ((uint32_t *) in), NUM_BRANCHES);
    // Execute SPARKLE with a slim number of steps
    sparkle_opt(state, NUM_BRANCHES, STEPS_SLIM);
    in_blen -= MSGBLOCK_BLEN;
    in += MSGBLOCK_BLEN;
  }

  // The last block can be between 0 and 16 bytes long (it can only be 0 when
  // inlen is 0). It is padded only when its length is shorter than 16 bytes.

  memcpy(lastblk, in, in_blen);
  if (in_blen < MSGBLOCK_BLEN) {
    ((uchar_t *) lastblk)[in_blen] = 0x80;
  }
  // Add the (padded) last block to the state
  injectm_opt(state, lastblk, NUM_BRANCHES);
  // Const_M is added to y3, which is state[7]
  state[NUM_BRANCHES-1] ^= ((in_blen < MSGBLOCK_BLEN) ? 0x01000000 :
0x02000000);
  // Execute SPARKLE with a big number of steps
  sparkle_opt(state, NUM_BRANCHES, STEPS_BIG);

  // Squeeze to produce the message digest

  memcpy(out, state, SQZBLOCK_BLEN);
  sparkle_opt(state, NUM_BRANCHES, STEPS_SLIM);
  memcpy(&(out[SQZBLOCK_BLEN]), state, SQZBLOCK_BLEN);
  sparkle_opt(state, NUM_BRANCHES, STEPS_SLIM);
  memcpy(&(out[2*SQZBLOCK_BLEN]), state, SQZBLOCK_BLEN);

  return 0;
}
