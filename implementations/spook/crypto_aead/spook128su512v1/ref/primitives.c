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
#include <string.h>
#include <stdint.h>

#include "primitives.h"
#include "utils.h"

#define CLYDE_128_NS 6                // Number of steps
#define CLYDE_128_NR 2 * CLYDE_128_NS // Number of rounds
#define SHADOW_NS 6                   // Number of steps
#define SHADOW_NR 2 * SHADOW_NS       // Number of rounds

#define LS_ROWS 4      // Rows in the LS design
#define LS_ROW_BYTES 4 // number of bytes per row in the LS design
#define MLS_BUNDLES                                                            \
  (SHADOW_NBYTES / (LS_ROWS* LS_ROW_BYTES)) // Bundles in the mLS design

static void sbox_layer(uint32_t* state);
static void sbox_layer_inv(uint32_t* state);
static void lbox(uint32_t* x, uint32_t* y);
static void lbox_inv(uint32_t* x, uint32_t* y);
static void lbox_layer(uint32_t* state);
static void lbox_layer_inv(uint32_t* state);
static void bytes2state(uint32_t* state, const unsigned char* byte);
static void state2bytes(unsigned char* bytes, const uint32_t* state);
static void xor_ls_state(uint32_t* state, const uint32_t* x);
static void add_rc(uint32_t state[LS_ROWS], unsigned int round,
                   unsigned int shift);
static void tweakey(unsigned char tk[3][CLYDE128_NBYTES],
                    const unsigned char* k, const unsigned char* t);
static void dbox_mls_layer(uint32_t state[MLS_BUNDLES][LS_ROWS]);

// Round constants for Clyde-128
static const uint32_t clyde128_rc[CLYDE_128_NR][LS_ROWS] = {
  { 1, 0, 0, 0 }, // 0
  { 0, 1, 0, 0 }, // 1
  { 0, 0, 1, 0 }, // 2
  { 0, 0, 0, 1 }, // 3
  { 1, 1, 0, 0 }, // 4
  { 0, 1, 1, 0 }, // 5
  { 0, 0, 1, 1 }, // 6
  { 1, 1, 0, 1 }, // 7
  { 1, 0, 1, 0 }, // 8
  { 0, 1, 0, 1 }, // 9
  { 1, 1, 1, 0 }, // 10
  { 0, 1, 1, 1 }  // 11
};

// Apply a S-box layer to a Clyde-128 state.
static void sbox_layer(uint32_t* state) {
  uint32_t y1 = (state[0] & state[1]) ^ state[2];
  uint32_t y0 = (state[3] & state[0]) ^ state[1];
  uint32_t y3 = (y1 & state[3]) ^ state[0];
  uint32_t y2 = (y0 & y1) ^ state[3];
  state[0] = y0;
  state[1] = y1;
  state[2] = y2;
  state[3] = y3;
}

// Apply a inverse S-box layer to a Clyde-128 state.
static void sbox_layer_inv(uint32_t* state) {
  uint32_t y3 = (state[0] & state[1]) ^ state[2];
  uint32_t y0 = (state[1] & y3) ^ state[3];
  uint32_t y1 = (y3 & y0) ^ state[0];
  uint32_t y2 = (y0 & y1) ^ state[1];
  state[0] = y0;
  state[1] = y1;
  state[2] = y2;
  state[3] = y3;
}

// Apply a L-box to a pair of Clyde-128 rows.
static void lbox(uint32_t* x, uint32_t* y) {
  uint32_t a, b, c, d;
  a = *x ^ rotr(*x, 12);
  b = *y ^ rotr(*y, 12);
  a = a ^ rotr(a, 3);
  b = b ^ rotr(b, 3);
  a = a ^ rotr(*x, 17);
  b = b ^ rotr(*y, 17);
  c = a ^ rotr(a, 31);
  d = b ^ rotr(b, 31);
  a = a ^ rotr(d, 26);
  b = b ^ rotr(c, 25);
  a = a ^ rotr(c, 15);
  b = b ^ rotr(d, 15);
  *x = a;
  *y = b;
}

// Apply a inverse L-box to a pair of Clyde-128 rows.
static void lbox_inv(uint32_t* x, uint32_t* y) {
  uint32_t a, b, c, d;
  a = *x ^ rotr(*x, 25);
  b = *y ^ rotr(*y, 25);
  c = *x ^ rotr(a, 31);
  d = *y ^ rotr(b, 31);
  c = c ^ rotr(a, 20);
  d = d ^ rotr(b, 20);
  a = c ^ rotr(c, 31);
  b = d ^ rotr(d, 31);
  c = c ^ rotr(b, 26);
  d = d ^ rotr(a, 25);
  a = a ^ rotr(c, 17);
  b = b ^ rotr(d, 17);
  a = rotr(a, 16);
  b = rotr(b, 16);
  *x = a;
  *y = b;
}

// Apply a L-box layer to a Clyde-128 state.
static void lbox_layer(uint32_t* state) {
  lbox(&state[0], &state[1]);
  lbox(&state[2], &state[3]);
}

// Apply inverse L-box layer to a Clyde-128 state.
static void lbox_layer_inv(uint32_t* state) {
  lbox_inv(&state[0], &state[1]);
  lbox_inv(&state[2], &state[3]);
}

// Convert bytes to a Clyde-128 state. Bytes are in ordered by row (first-row
// first), and in little-endian order inside a row.
static void bytes2state(uint32_t* state, const unsigned char* bytes) {
  for (unsigned int row = 0; row < LS_ROWS; row++) {
    state[row] = le32u_dec(bytes + 4 * row);
  }
}

// Convert Clyde-128 state to bytes. Bytes are in ordered by row (first-row
// first), and in little-endian order inside a row.
static void state2bytes(unsigned char* bytes, const uint32_t* state) {
  for (unsigned int row = 0; row < LS_ROWS; row++) {
    le32u_enc(bytes + 4 * row, state[row]);
  }
}

// XOR the Clyde-128 state x into state.
static void xor_ls_state(uint32_t* state, const uint32_t* x) {
  for (unsigned int i = 0; i < LS_ROWS; i++) {
    state[i] ^= x[i];
  }
}

// XOR the Clyde-128 round constant of given round into state, left shifting
// each constant by shift.
static void add_rc(uint32_t state[LS_ROWS], unsigned int round,
                   unsigned int shift) {
  for (unsigned int i = 0; i < LS_ROWS; i++) {
    state[i] ^= clyde128_rc[round][i] << shift;
  }
}

// Key schedule for Clyde-128. Generate 3 Clyde-128 states from key k and tweak
// t.
static void tweakey(unsigned char tk[3][CLYDE128_NBYTES],
                    const unsigned char* k, const unsigned char* t) {
  const unsigned char* t0 = t;
  const unsigned char* t1 = t + CLYDE128_NBYTES / 2;
  unsigned char tx[CLYDE128_NBYTES / 2];
  xor_bytes(tx, t0, t1, CLYDE128_NBYTES / 2);
  // TK[0]
  xor_bytes(tk[0], k, t, CLYDE128_NBYTES);
  // TK[1]
  xor_bytes(tk[1], k, tx, CLYDE128_NBYTES / 2);
  xor_bytes(tk[1] + CLYDE128_NBYTES / 2, k + CLYDE128_NBYTES / 2, t0,
            CLYDE128_NBYTES / 2);
  // TK[2]
  xor_bytes(tk[2], k, t1, CLYDE128_NBYTES / 2);
  xor_bytes(tk[2] + CLYDE128_NBYTES / 2, k + CLYDE128_NBYTES / 2, tx,
            CLYDE128_NBYTES / 2);
}

// Apply a D-box layer to a Shadow state.
static void dbox_mls_layer(uint32_t state[MLS_BUNDLES][LS_ROWS]) {
  for (unsigned int row = 0; row < LS_ROWS; row++) {
#if SMALL_PERM
    uint32_t x = state[0][row];
    uint32_t y = state[1][row];
    uint32_t z = state[2][row];
    state[0][row] = x ^ y ^ z;
    state[1][row] = x ^ z;
    state[2][row] = x ^ y;
#else
    uint32_t w = state[0][row];
    uint32_t x = state[1][row];
    uint32_t y = state[2][row];
    uint32_t z = state[3][row];
    uint32_t u = w ^ x;
    uint32_t v = y ^ z;
    state[0][row] = x ^ v;
    state[1][row] = w ^ v;
    state[2][row] = u ^ z;
    state[3][row] = u ^ y;
#endif // SMALL_PERM
  }
}

// Clyde-128 TBC.
// Output in buffer c the TBC for block m, tweak t and key k.
// All buffers have length CLYDE128_NBYTES.
void clyde128_encrypt(unsigned char* c, const unsigned char* m,
                      const unsigned char* t, const unsigned char* k) {
  // Key schedule
  unsigned char tkb[3][CLYDE128_NBYTES];
  uint32_t tk[3][LS_ROWS];
  tweakey(tkb, k, t);
  bytes2state(tk[0], tkb[0]);
  bytes2state(tk[1], tkb[1]);
  bytes2state(tk[2], tkb[2]);

  // Datapath
  uint32_t state[LS_ROWS];
  bytes2state(state, m);
  xor_ls_state(state, tk[0]);
  for (unsigned int s = 0; s < CLYDE_128_NS; s++) {
    for (unsigned int rho = 0; rho < 2; rho++) {
      unsigned int r = 2 * s + rho;
      sbox_layer(state);
      lbox_layer(state);
      add_rc(state, r, 0);
    }
    xor_ls_state(state, tk[(s + 1) % 3]);
  }
  state2bytes(c, state);
}

// Clyde-128 inverse TBC.
// Output in buffer m the inverse TBC for block c, tweak t and key k.
// All buffers have length CLYDE128_NBYTES.
void clyde128_decrypt(unsigned char* m, const unsigned char* c,
                      const unsigned char* t, const unsigned char* k) {
  // Key schedule
  unsigned char tkb[3][CLYDE128_NBYTES];
  uint32_t tk[3][LS_ROWS];
  tweakey(tkb, k, t);
  bytes2state(tk[0], tkb[0]);
  bytes2state(tk[1], tkb[1]);
  bytes2state(tk[2], tkb[2]);

  // Datapath
  uint32_t state[LS_ROWS];
  bytes2state(state, c);
  for (int s = CLYDE_128_NS - 1; s >= 0; s--) {
    xor_ls_state(state, tk[(s + 1) % 3]);
    for (int rho = 1; rho >= 0; rho--) {
      unsigned int r = 2 * s + rho;
      add_rc(state, r, 0);
      lbox_layer_inv(state);
      sbox_layer_inv(state);
    }
  }
  xor_ls_state(state, tk[0]);
  state2bytes(m, state);
}

// Shadow permutation. Updates x (array of SHADOW_NBYTES bytes).
void shadow(unsigned char* x) {
  uint32_t state[MLS_BUNDLES][LS_ROWS];
  for (unsigned int b = 0; b < MLS_BUNDLES; b++) {
    bytes2state(state[b], x + (b * SHADOW_NBYTES / MLS_BUNDLES));
  }
  for (unsigned int s = 0; s < SHADOW_NS; s++) {
    for (unsigned int b = 0; b < MLS_BUNDLES; b++) {
      sbox_layer(state[b]);
      lbox_layer(state[b]);
      add_rc(state[b], 2 * s, b);
      sbox_layer(state[b]);
    }
    dbox_mls_layer(state);
    for (unsigned int b = 0; b < MLS_BUNDLES; b++) {
      add_rc(state[b], 2 * s + 1, b);
    }
  }
  for (unsigned int b = 0; b < MLS_BUNDLES; b++) {
    state2bytes(x + (b * SHADOW_NBYTES / MLS_BUNDLES), state[b]);
  }
}
