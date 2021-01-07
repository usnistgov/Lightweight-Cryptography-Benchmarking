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
#include "sparkle_opt.h"


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


// The message to be hashed is stored in arrays of type unsigned char. Casting
// such an unsigned-char-pointer to an uint32_t-pointer increases alignment
// requirements, i.e. the start address of the array has to be even on 16-bit
// architectures or a multiple of four (i.e. 4-byte aligned) on 32-bit and
// 64-bit platforms. The following preprocessor statements help to determine
// the alignment requirements for a uint32_t pointer.

#define MIN_SIZE(a, b) ((sizeof(a) < sizeof(b)) ? sizeof(a) : sizeof(b))
#if defined(_MSC_VER) && !defined(__clang__) && !defined(__ICL)
#define UI32_ALIGN_BYTES MIN_SIZE(unsigned __int32, size_t)
#else
#include <stdint.h>
#define UI32_ALIGN_BYTES MIN_SIZE(uint32_t, uint_fast8_t)
#endif


// Injection of a 16-byte block of the message to the state. According to the
// specification, the Feistel function is performed on a message block that is
// padded with 0-bytes to reach a length of STATE_BYTES/2 bytes (i.e. 24 bytes
// for ESCH256, 32 bytes for ESCH384). However, this padding can be omitted by
// adapting the Feistel function accordingly. The third parameter indicates
// whether the uint8_t-pointer 'in' is properly aligned to permit casting to a
// uint32_t-pointer. If this is the case then array 'in' is processed directly,
// otherwise it is first copied to an aligned buffer. 

static void add_msg_blk(uint32_t *state, const uint8_t *in, int aligned)
{
  uint32_t buffer[RATE_WORDS];
  uint32_t *in32;
  uint32_t tmpx = 0, tmpy = 0;
  int i;
  
  if (aligned) {  // 'in' can be casted to uint32_t pointer
    in32 = (uint32_t *) in;
  } else {  // 'in' is not sufficiently aligned for casting
    memcpy(buffer, in, RATE_BYTES);
    in32 = (uint32_t *) &buffer;
  }
  
  for(i = 0; i < RATE_WORDS; i += 2) {
    tmpx ^= in32[i];
    tmpy ^= in32[i+1];
  }
  tmpx = ELL(tmpx);
  tmpy = ELL(tmpy);
  for(i = 0; i < RATE_WORDS; i += 2) {
    state[i] ^= (in32[i] ^ tmpy);
    state[i+1] ^= (in32[i+1] ^ tmpx);
  }
  for(i = RATE_WORDS; i < (STATE_WORDS/2); i += 2) {
    state[i] ^= tmpy;
    state[i+1] ^= tmpx;
  }
}


// Injection of the last message block to the state. Since this last block may
// require padding, it is always copied to a buffer.

static void add_msg_blk_last(uint32_t *state, const uint8_t *in, size_t inlen)
{
  uint32_t buffer[RATE_WORDS];
  uint8_t *bufptr;
  uint32_t tmpx = 0, tmpy = 0;
  int i;
  
  memcpy(buffer, in, inlen);
  if (inlen < RATE_BYTES) {  // padding
    bufptr = ((uint8_t *) buffer) + inlen;
    memset(bufptr, 0, (RATE_BYTES - inlen));
    *bufptr = 0x80;
  }
  
  for(i = 0; i < RATE_WORDS; i += 2) {
    tmpx ^= buffer[i];
    tmpy ^= buffer[i+1];
  }
  tmpx = ELL(tmpx);
  tmpy = ELL(tmpy);
  for(i = 0; i < RATE_WORDS; i += 2) {
    state[i] ^= (buffer[i] ^ tmpy);
    state[i+1] ^= (buffer[i+1] ^ tmpx);
  }
  for(i = RATE_WORDS; i < (STATE_WORDS/2); i += 2) {
    state[i] ^= tmpy;
    state[i+1] ^= tmpx;
  }
}


///////////////////////////////////////////////////////////////////////////////
///////////// LOW-LEVEL HASH FUNCTIONS (FOR USE WITH FELICS-HASH) /////////////
///////////////////////////////////////////////////////////////////////////////


// The Initialize function sets all branches of the state to 0.

void Initialize(uint32_t *state)
{
  int i;
  
  for (i = 0; i < STATE_WORDS; i++)
    state[i] = 0;
}


// The ProcessMessage function absorbs the message into the state (in blocks of
// 16 bytes). According to the specification, the constant Const_M is first
// transformed via the inverse Feistel function, added to the (padded) message
// block, and finally injected to the state via the Feistel function. Since the
// Feistel function and the inverse Feistel function cancel out, we can simply
// inject the constant directly to the state.

void ProcessMessage(uint32_t *state, const UChar *in, size_t inlen)
{
  // check whether 'in' can be casted to uint32_t pointer
  int aligned = ((size_t) in) % UI32_ALIGN_BYTES == 0;
  // printf("Address of 'in': %p\n", in);
  
  // Main Hashing Loop
  
  while (inlen > RATE_BYTES) {
    // addition of a message block to the state
    add_msg_blk(state, in, aligned);
    // execute SPARKLE with slim number of steps
    sparkle_opt(state, STATE_BRANS, SPARKLE_STEPS_SLIM);
    inlen -= RATE_BYTES;
    in += RATE_BYTES;
  }
  
  // Hashing of Last Block
  
  // addition of constant M1 or M2 to the state
  state[STATE_BRANS-1] ^= ((inlen < RATE_BYTES) ? CONST_M1 : CONST_M2);
  // addition of last msg block (incl. padding)
  add_msg_blk_last(state, in, inlen);
  // execute SPARKLE with big number of steps
  sparkle_opt(state, STATE_BRANS, SPARKLE_STEPS_BIG);
}


// The Finalize function generates the message digest by "squeezing" (i.e. by
// calling SPARKLE with a slim number of steps) until the digest has reached a
// byte-length of DIGEST_BYTES.

void Finalize(uint32_t *state, UChar *out)
{
  size_t outlen;
  
  memcpy(out, state, RATE_BYTES);
  outlen = RATE_BYTES;
  out += RATE_BYTES;
  while (outlen < DIGEST_BYTES) {
    sparkle_opt(state, STATE_BRANS, SPARKLE_STEPS_SLIM);
    memcpy(out, state, RATE_BYTES);
    outlen += RATE_BYTES;
    out += RATE_BYTES;
  }
}


///////////////////////////////////////////////////////////////////////////////
////////////// HIGH-LEVEL HASH FUNCTIONS (FOR USE WITH SUPERCOP) //////////////
///////////////////////////////////////////////////////////////////////////////


// To ensure compatibility with the SUPERCOP, the below implementation of 
// crypto_hash can handle overlapping input and output buffers.

int crypto_hash(UChar *out, const UChar *in, ULLInt inlen)
{
  uint32_t state[STATE_WORDS];
  size_t insize = (size_t) inlen;
  
  Initialize(state);
  ProcessMessage(state, in, insize);
  Finalize(state, out);
  
  return 0;
}
