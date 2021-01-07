///////////////////////////////////////////////////////////////////////////////
// encrypt.c: Reference C99 implementation of the AEAD algorithm SCHWAEMM.   //
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

// gencat_aead.c shall be used to generate the test vector output file. The
// test vector output file shall be provided in the corresponding
// crypto_aead/[algorithm]/ directory


#include <stddef.h>  // for size_t
#include <string.h>  // for memcpy, memset
#include "schwaemm_cfg.h"
#include "sparkle_ref.h"


typedef unsigned char UChar;
typedef unsigned long long int ULLInt;


#define KEY_WORDS   (SCHWAEMM_KEY_LEN/32)
#define KEY_BYTES   (SCHWAEMM_KEY_LEN/8)
#define NONCE_WORDS (SCHWAEMM_NONCE_LEN/32)
#define NONCE_BYTES (SCHWAEMM_NONCE_LEN/8)
#define TAG_WORDS   (SCHWAEMM_TAG_LEN/32)
#define TAG_BYTES   (SCHWAEMM_TAG_LEN/8)

#define STATE_BRANS (SPARKLE_STATE/64)
#define STATE_WORDS (SPARKLE_STATE/32)
#define STATE_BYTES (SPARKLE_STATE/8)
#define RATE_BRANS  (SPARKLE_RATE/64)
#define RATE_WORDS  (SPARKLE_RATE/32)
#define RATE_BYTES  (SPARKLE_RATE/8)
#define CAP_BRANS   (SPARKLE_CAPACITY/64)
#define CAP_WORDS   (SPARKLE_CAPACITY/32)
#define CAP_BYTES   (SPARKLE_CAPACITY/8)

#define CONST_A0 (((uint32_t) (0 ^ (1 << CAP_BRANS))) << 24)
#define CONST_A1 (((uint32_t) (1 ^ (1 << CAP_BRANS))) << 24)
#define CONST_M2 (((uint32_t) (2 ^ (1 << CAP_BRANS))) << 24)
#define CONST_M3 (((uint32_t) (3 ^ (1 << CAP_BRANS))) << 24)


///////////////////////////////////////////////////////////////////////////////
/////// HELPER FUNCTIONS AND MACROS (RHO1, RHO2, RATE-WHITENING, ETC.) ////////
///////////////////////////////////////////////////////////////////////////////


// The macro STATE_WORD expands to the address of the i-th word of the state,
// which is always an x-word if i is even and a y-word otherwise.

#define STATE_WORD(s, i) (((i) & 1) ? (&((s)->y[(i)/2])) : (&((s)->x[(i)/2])))


// Rho and rate-whitening for the authentication of associated data.

static void rho_whi_aut(SparkleState *state, const uint8_t *in, size_t inlen)
{
  uint32_t inbuf[RATE_WORDS] = { 0 };
  uint32_t *left_word, *right_word, tmp;  // Feistel-swap
  int i;
  
  memcpy(inbuf, in, inlen);
  if (inlen < RATE_BYTES)  // padding (only for last block)
    *(((uint8_t *) inbuf) + inlen) = 0x80;
  
  // Rho1 part1: Feistel swap of the rate-part of the state
  for (i = 0; i < RATE_BRANS; i++) {
    left_word = STATE_WORD(state, i);
    right_word = STATE_WORD(state, (RATE_BRANS + i));
    tmp = *left_word;
    *left_word = *right_word;
    *right_word ^= tmp;
  }
  // Rho1 part2: rate-part of state is XORed with assoc data
  for (i = 0; i < RATE_BRANS; i++) {
    state->x[i] ^= inbuf[2*i];
    state->y[i] ^= inbuf[2*i+1];
  }
  // Rate-whitening: capacity-part is XORed to the rate-part
  for (i = 0; i < RATE_BRANS; i++) {
    state->x[i] ^= state->x[RATE_BRANS+(i%CAP_BRANS)];
    state->y[i] ^= state->y[RATE_BRANS+(i%CAP_BRANS)];
  }
}


// Rho and rate-whitening for the encryption of plaintext.

static void rho_whi_enc(SparkleState *state, uint8_t *out, const uint8_t *in, \
                        size_t inlen)
{
  uint32_t inbuf[RATE_WORDS] = { 0 }, outbuf[RATE_WORDS];
  uint32_t *left_word, *right_word, tmp;  // Feistel-swap
  int i;
  
  memcpy(inbuf, in, inlen);
  if (inlen < RATE_BYTES)  // padding (only for last block)
    *(((uint8_t *) inbuf) + inlen) = 0x80;
  
  // Rho2: ciphertext = plaintext XOR rate-part of the state
  for (i = 0; i < RATE_BRANS; i++) {
    outbuf[2*i] = inbuf[2*i] ^ state->x[i];
    outbuf[2*i+1] = inbuf[2*i+1] ^ state->y[i];
  }
  // Rho1 part1: Feistel swap of the rate-part of the state
  for (i = 0; i < RATE_BRANS; i++) {
    left_word = STATE_WORD(state, i);
    right_word = STATE_WORD(state, (RATE_BRANS + i));
    tmp = *left_word;
    *left_word = *right_word;
    *right_word ^= tmp;
  }
  // Rho1 part2: rate-part of state is XORed with ciphertext
  for (i = 0; i < RATE_BRANS; i++) {
    state->x[i] ^= inbuf[2*i];
    state->y[i] ^= inbuf[2*i+1];
  }
  // Rate-whitening: capacity-part is XORed to the rate-part
  for (i = 0; i < RATE_BRANS; i++) {
    state->x[i] ^= state->x[RATE_BRANS+(i%CAP_BRANS)];
    state->y[i] ^= state->y[RATE_BRANS+(i%CAP_BRANS)];
  }
  memcpy(out, outbuf, inlen);
}


// Rho and rate-whitening for the decryption of ciphertext.

static void rho_whi_dec(SparkleState *state, uint8_t *out, const uint8_t *in, \
                        size_t inlen)
{
  uint32_t inbuf[RATE_WORDS] = { 0 }, outbuf[RATE_WORDS];
  SparkleState statebuf;
  uint32_t *left_word, *right_word, tmp;  // Feistel-swap
  int i;
  
  memcpy(inbuf, in, inlen);
  memcpy(&statebuf, state, sizeof(SparkleState));
  if (inlen < RATE_BYTES)  // padding (only for last block!)
    *(((uint8_t *) inbuf) + inlen) = 0x80;
  
  // Rho2': plaintext = ciphertext XOR rate-part of the state
  for (i = 0; i < RATE_BRANS; i++) {
    outbuf[2*i] = inbuf[2*i] ^ state->x[i];
    outbuf[2*i+1] = inbuf[2*i+1] ^ state->y[i];
  }
  // Rho1' part1: Feistel swap of the rate-part of the state
  for (i = 0; i < RATE_BRANS; i++) {
    left_word = STATE_WORD(state, i);
    right_word = STATE_WORD(state, (RATE_BRANS + i));
    tmp = *left_word;
    *left_word = *right_word;
    *right_word ^= tmp;
  }
  if (inlen < RATE_BYTES) {
    // padding of last block of plaintext (computed by Rho2')
    memset((((uint8_t *) outbuf) + inlen), 0, (RATE_BYTES - inlen));
    *(((uint8_t *) outbuf) + inlen) = 0x80;
    // Rho1 part2: rate-part of state is XORed with plaintext
    for (i = 0; i < RATE_BRANS; i++) {
      state->x[i] ^= outbuf[2*i];
      state->y[i] ^= outbuf[2*i+1];
    }
  } else {
    // Rho1' part2: rate-part XORed with orig rate and ciphertext
    for (i = 0; i < RATE_BRANS; i++) {
      state->x[i] ^= statebuf.x[i] ^ inbuf[2*i];
      state->y[i] ^= statebuf.y[i] ^ inbuf[2*i+1];
    }
  }
  // Rate-whitening: capacity-part is XORed to the rate-part
  for (i = 0; i < RATE_BRANS; i++) {
    state->x[i] ^= state->x[RATE_BRANS+(i%CAP_BRANS)];
    state->y[i] ^= state->y[RATE_BRANS+(i%CAP_BRANS)];
  }
  memcpy(out, outbuf, inlen);
}


///////////////////////////////////////////////////////////////////////////////
///////////// LOW-LEVEL AEAD FUNCTIONS (FOR USE WITH FELICS-AEAD) /////////////
///////////////////////////////////////////////////////////////////////////////


// The Initialize function loads nonce and key into the state and executes the
// SPARKLE permutation with the big number of steps.

void Initialize(SparkleState *state, const uint8_t *key, const uint8_t *nonce)
{
  uint32_t keybuf[KEY_WORDS], noncebuf[NONCE_WORDS];
  int i;
  
  // to prevent (potentially) unaligned memory accesses
  memcpy(keybuf, key, KEY_BYTES);
  memcpy(noncebuf, nonce, NONCE_BYTES);
  // load nonce into the rate-part of the state
  for (i = 0; i < NONCE_WORDS/2; i++) {
    state->x[i] = noncebuf[2*i];
    state->y[i] = noncebuf[2*i+1];
  }
  // load key into the capacity-part of the sate
  for (i = 0; i < KEY_WORDS/2; i++) {
    state->x[RATE_BRANS+i] = keybuf[2*i];
    state->y[RATE_BRANS+i] = keybuf[2*i+1];
  }
  // execute SPARKLE with big number of steps
  sparkle_ref(state, STATE_BRANS, SPARKLE_STEPS_BIG);
}


// The ProcessAssocData function absorbs the associated data, which becomes
// only authenticated but not encrypted, into the state (in blocks of size
// RATE_BYTES). Note that this function MUST NOT be called when the length of
// the associated data is 0.

void ProcessAssocData(SparkleState *state, const uint8_t *in, size_t inlen)
{
  // Main Authentication Loop
  
  while (inlen > RATE_BYTES) {
    // combined Rho and rate-whitening operation
    rho_whi_aut(state, in, RATE_BYTES);
    // execute SPARKLE with slim number of steps
    sparkle_ref(state, STATE_BRANS, SPARKLE_STEPS_SLIM);
    inlen -= RATE_BYTES;
    in += RATE_BYTES;
  }
  
  // Authentication of Last Block
  
  // addition of constant A0 or A1 to the state
  state->y[STATE_BRANS-1] ^= ((inlen < RATE_BYTES) ? CONST_A0 : CONST_A1);
  // combined Rho and rate-whitening operation
  rho_whi_aut(state, in, inlen);
  // execute SPARKLE with big number of steps
  sparkle_ref(state, STATE_BRANS, SPARKLE_STEPS_BIG);
}


// The ProcessPlainText function encrypts the plaintext (in blocks of size
// RATE_BYTES) and generates the respective ciphertext. The uint8_t-array 'in'
// contains the plaintext and the ciphertext is written to uint8_t-array 'out'
// ('in' and 'out' can be the same array, i.e. they can have the same start
// address). Note that this function MUST NOT be called when the length of the
// plaintext is 0.

void ProcessPlainText(SparkleState *state, uint8_t *out, const uint8_t *in, \
                      size_t inlen)
{
  // Main Encryption Loop
  
  while (inlen > RATE_BYTES) {
    // combined Rho and rate-whitening operation
    rho_whi_enc(state, out, in, RATE_BYTES);
    // execute SPARKLE with slim number of steps
    sparkle_ref(state, STATE_BRANS, SPARKLE_STEPS_SLIM);
    inlen -= RATE_BYTES;
    out += RATE_BYTES;
    in += RATE_BYTES;
  }
  
  // Encryption of Last Block
  
  // addition of constant M2 or M3 to the state
  state->y[STATE_BRANS-1] ^= ((inlen < RATE_BYTES) ? CONST_M2 : CONST_M3);
  // combined Rho and rate-whitening (incl. padding)
  rho_whi_enc(state, out, in, inlen);
  // execute SPARKLE with big number of steps
  sparkle_ref(state, STATE_BRANS, SPARKLE_STEPS_BIG);
}


// The Finalize function adds the key to the capacity part of the state.

void Finalize(SparkleState *state, const uint8_t *key)
{
  uint32_t keybuf[KEY_WORDS];
  int i;
  
  // to prevent (potentially) unaligned memory accesses
  memcpy(keybuf, key, KEY_BYTES);
  // add key to the capacity-part of the state
  for (i = 0; i < KEY_WORDS/2; i++) {
    state->x[RATE_BRANS+i] ^= keybuf[2*i];
    state->y[RATE_BRANS+i] ^= keybuf[2*i+1];
  }
}


// The GenerateTag function generates an authentication tag.

void GenerateTag(SparkleState *state, uint8_t *tag)
{
  uint32_t tagbuf[TAG_WORDS];
  int i;
  
  for (i = 0; i < TAG_WORDS/2; i++) {
    tagbuf[2*i] = state->x[RATE_BRANS+i];
    tagbuf[2*i+1] = state->y[RATE_BRANS+i];
  }
  memcpy(tag, tagbuf, TAG_BYTES);
}


// The VerifyTag function checks whether the given authentication tag is valid.
// It performs a simple constant-time comparison and returns 0 if the provided
// tag matches the computed tag and -1 otherwise.

int VerifyTag(SparkleState *state, const uint8_t *tag)
{
  uint32_t tagbuf[TAG_WORDS], diff = 0;
  int i;
  
  // to prevent (potentially) unaligned memory accesses
  memcpy(tagbuf, tag, TAG_BYTES);
  // constant-time comparison: 0 if equal, -1 otherwise
  for (i = 0; i < TAG_WORDS/2; i++) {
    diff |= (state->x[RATE_BRANS+i] ^ tagbuf[2*i]);
    diff |= (state->y[RATE_BRANS+i] ^ tagbuf[2*i+1]);
  }
  
  return (((int) (diff == 0)) - 1);
}


// The ProcessCipherText function decrypts the ciphertext (in blocks of size
// RATE_BYTES) and generates the respective plaintext. The uint8_t-array 'in'
// contains the ciphertext and the plaintext is written to uint8_t-array 'out'
// ('in' and 'out' can be the same array, i.e. they can have the same start
// address). Note that this function MUST NOT be called when the length of the
// ciphertext is 0.

void ProcessCipherText(SparkleState *state, uint8_t *out, const uint8_t *in, \
                       size_t inlen)
{
  // Main Decryption Loop
  
  while (inlen > RATE_BYTES) {
    // combined Rho and rate-whitening operation
    rho_whi_dec(state, out, in, RATE_BYTES);
    // execute SPARKLE with slim number of steps
    sparkle_ref(state, STATE_BRANS, SPARKLE_STEPS_SLIM);
    inlen -= RATE_BYTES;
    out += RATE_BYTES;
    in += RATE_BYTES;
  }
  
  // Decryption of Last Block
  
  // addition of constant M2 or M3 to the state
  state->y[STATE_BRANS-1] ^= ((inlen < RATE_BYTES) ? CONST_M2 : CONST_M3);
  // combined Rho and rate-whitening (incl. padding)
  rho_whi_dec(state, out, in, inlen);
  // execute SPARKLE with big number of steps
  sparkle_ref(state, STATE_BRANS, SPARKLE_STEPS_BIG);
}


///////////////////////////////////////////////////////////////////////////////
////////////// HIGH-LEVEL AEAD FUNCTIONS (FOR USE WITH SUPERCOP) //////////////
///////////////////////////////////////////////////////////////////////////////


// High-level encryption function from SUPERCOP.
// nsec is kept for compatibility with SUPERCOP, but is not used.

int crypto_aead_encrypt(UChar *c, ULLInt *clen, const UChar *m, ULLInt mlen, \
  const UChar *ad, ULLInt adlen, const UChar *nsec, const UChar *npub,       \
  const UChar *k)
{
  SparkleState state;
  size_t msize = (size_t) mlen;
  size_t adsize = (size_t) adlen;
  
  Initialize(&state, k, npub);
  if (adsize) ProcessAssocData(&state, ad, adsize);
  if (msize) ProcessPlainText(&state, c, m, msize);
  Finalize(&state, k);
  GenerateTag(&state, (c + msize));
  *clen = msize;
  *clen += TAG_BYTES;
  
  return 0;
}


// High-level decryption function from SUPERCOP.
// nsec is kept for compatibility with SUPERCOP, but is not used.

int crypto_aead_decrypt(UChar *m, ULLInt *mlen, UChar *nsec, const UChar *c, \
  ULLInt clen, const UChar *ad, ULLInt adlen, const UChar *npub,             \
  const UChar *k)
{
  SparkleState state;
  size_t csize = (size_t) (clen - TAG_BYTES);
  size_t adsize = (size_t) adlen;
  int retval;
  
  Initialize(&state, k, npub);
  if (adsize) ProcessAssocData(&state, ad, adsize);
  if (csize) ProcessCipherText(&state, m, c, csize);
  Finalize(&state, k);
  retval = VerifyTag(&state, (c + csize));
  *mlen = csize;
  
  return retval;
}
