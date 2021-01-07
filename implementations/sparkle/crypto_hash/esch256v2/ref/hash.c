///////////////////////////////////////////////////////////////////////////////
// hash.c: Optimized C99 implementation of the hash function ESCH.           //
// This file is part of the SPARKLE submission to NIST's LW Crypto Project.  //
// Version 1.1.2 (2020-10-30), see <http://www.cryptolux.org/> for updates.  //
// Authors: The SPARKLE Group (C. Beierle, A. Biryukov, L. Cardoso dos       //
// Santos, J. Groszschaedl, L. Perrin, A. Udovenko, V. Velichkov, Q. Wang).  //
// License: GPLv3 (see LICENSE file), other licenses available upon request. //
// Copyright (C) 2019-2020 University of Luxembourg <http://www.uni.lu/>.    //
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


#include <stddef.h>  // for size_t
#include <string.h>  // for memcpy, memset
#include "esch_cfg.h"
#include "sparkle_ref.h"


typedef unsigned char UChar;
typedef unsigned long long int ULLInt;


#define DIGEST_WORDS (ESCH_DIGEST_LEN/32)
#define DIGEST_BYTES (ESCH_DIGEST_LEN/8)

#define STATE_BRANS  (SPARKLE_STATE/64)
#define STATE_WORDS  (SPARKLE_STATE/32)
#define STATE_BYTES  (SPARKLE_STATE/8)
#define RATE_BRANS   (SPARKLE_RATE/64)
#define RATE_WORDS   (SPARKLE_RATE/32)
#define RATE_BYTES   (SPARKLE_RATE/8)
#define CAP_BRANS    (SPARKLE_CAPACITY/64)
#define CAP_WORDS    (SPARKLE_CAPACITY/32)
#define CAP_BYTES    (SPARKLE_CAPACITY/8)

#define CONST_M1 (((uint32_t) 1) << 24)
#define CONST_M2 (((uint32_t) 2) << 24)


///////////////////////////////////////////////////////////////////////////////
/////// HELPER FUNCTIONS AND MACROS (INJECTION OF MESSAGE BLOCK, ETC.) ////////
///////////////////////////////////////////////////////////////////////////////


#define ROT(x, n) (((x) >> (n)) | ((x) << (32-(n))))
#define ELL(x) (ROT(((x) ^ ((x) << 16)), 16))


// Injection of a 16-byte block of the message to the state.

static void add_msg_blk(SparkleState *state, const uint8_t *in, size_t inlen)
{
  uint32_t buffer[STATE_WORDS/2] = { 0 };
  uint32_t tmpx = 0, tmpy = 0;
  int i;
  
  memcpy(buffer, in, inlen);
  if (inlen < RATE_BYTES)  // padding
    *(((uint8_t *) buffer) + inlen) = 0x80;
  
  // Feistel function part 1: computation of ELL(tmpx) and ELL(tmpy)
  for(i = 0; i < (STATE_WORDS/2); i += 2) {
    tmpx ^= buffer[i];
    tmpy ^= buffer[i+1];
  }
  tmpx = ELL(tmpx);
  tmpy = ELL(tmpy);
  // Feistel function part 2: state is XORed with tmpx/tmpy and msg
  for(i = 0; i < (STATE_BRANS/2); i++) {
    state->x[i] ^= (buffer[2*i] ^ tmpy);
    state->y[i] ^= (buffer[2*i+1] ^ tmpx);
  }
}


///////////////////////////////////////////////////////////////////////////////
///////////// LOW-LEVEL HASH FUNCTIONS (FOR USE WITH FELICS-HASH) /////////////
///////////////////////////////////////////////////////////////////////////////


// The Initialize function sets all branches of the state to 0.

void Initialize(SparkleState *state)
{
  int i;
  
  for (i = 0; i < STATE_BRANS; i++)
    state->x[i] = state->y[i] = 0;
}


// The ProcessMessage function absorbs the message into the state (in blocks of
// 16 bytes). According to the specification, the constant Const_M is first
// transformed via the inverse Feistel function, added to the (padded) message
// block, and finally injected to the state via the Feistel function. Since the
// Feistel function and the inverse Feistel function cancel out, we can simply
// inject the constant directly to the state.

void ProcessMessage(SparkleState *state, const UChar *in, size_t inlen)
{
  // Main Hashing Loop
  
  while (inlen > RATE_BYTES) {
    // addition of a message block to the state
    add_msg_blk(state, in, RATE_BYTES);
    // execute SPARKLE with slim number of steps
    sparkle_ref(state, STATE_BRANS, SPARKLE_STEPS_SLIM);
    inlen -= RATE_BYTES;
    in += RATE_BYTES;
  }
  
  // Hashing of Last Block
  
  // addition of constant M1 or M2 to the state
  state->y[(STATE_BRANS/2)-1] ^= ((inlen < RATE_BYTES) ? CONST_M1 : CONST_M2);
  // addition of last msg block (incl. padding)
  add_msg_blk(state, in, inlen);
  // execute SPARKLE with big number of steps
  sparkle_ref(state, STATE_BRANS, SPARKLE_STEPS_BIG);
}


// The Finalize function generates the message digest by "squeezing" (i.e. by
// calling SPARKLE with a slim number of steps) until the digest has reached a
// byte-length of DIGEST_BYTES.

void Finalize(SparkleState *state, UChar *out)
{
  uint32_t buffer[DIGEST_WORDS];
  int i, outlen = 0;
  
  for (i = 0; i < RATE_BRANS; i++) {
    buffer[outlen++] = state->x[i];
    buffer[outlen++] = state->y[i];
  }
  while (outlen < DIGEST_WORDS) {
    sparkle_ref(state, STATE_BRANS, SPARKLE_STEPS_SLIM);
    for (i = 0; i < RATE_BRANS; i++) {
      buffer[outlen++] = state->x[i];
      buffer[outlen++] = state->y[i];
    }
  }
  memcpy(out, buffer, DIGEST_BYTES);
}


///////////////////////////////////////////////////////////////////////////////
////////////// HIGH-LEVEL HASH FUNCTIONS (FOR USE WITH SUPERCOP) //////////////
///////////////////////////////////////////////////////////////////////////////


// To ensure compatibility with the SUPERCOP, the below implementation of 
// crypto_hash can handle overlapping input and output buffers.

int crypto_hash(UChar *out, const UChar *in, ULLInt inlen)
{
  SparkleState state;
  size_t insize = (size_t) inlen;
  
  Initialize(&state);
  ProcessMessage(&state, in, insize);
  Finalize(&state, out);
  
  return 0;
}
