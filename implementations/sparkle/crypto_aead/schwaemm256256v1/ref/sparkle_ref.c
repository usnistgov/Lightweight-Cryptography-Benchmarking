///////////////////////////////////////////////////////////////////////////////
// sparkle_ref.c: Reference C implementation of the SPARKLE permutation.     //
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

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include "sparkle_ref.h"

#define ROT(x, n) (((x) >> (n)) | ((x) << (32-(n))))
#define ELL(x) (ROT(((x) ^ ((x) << 16)), 16))

// 4-round ARX-box
#define ARXBOX(x, y, c)                     \
  (x) += ROT((y), 31), (y) ^= ROT((x), 24), \
  (x) ^= (c),                               \
  (x) += ROT((y), 17), (y) ^= ROT((x), 17), \
  (x) ^= (c),                               \
  (x) += (y),          (y) ^= ROT((x), 31), \
  (x) ^= (c),                               \
  (x) += ROT((y), 24), (y) ^= ROT((x), 16), \
  (x) ^= (c)

// Inverse of 4-round ARX-box
#define ARXBOX_INV(x, y, c)                 \
  (x) ^= (c),                               \
  (y) ^= ROT((x), 16), (x) -= ROT((y), 24), \
  (x) ^= (c),                               \
  (y) ^= ROT((x), 31), (x) -= (y),          \
  (x) ^= (c),                               \
  (y) ^= ROT((x), 17), (x) -= ROT((y), 17), \
  (x) ^= (c),                               \
  (y) ^= ROT((x), 24), (x) -= ROT((y), 31)

// Round constants
static const uint32_t RCON[MAX_BRANCHES] = {      \
  0xB7E15162, 0xBF715880, 0x38B4DA56, 0x324E7738, \
  0xBB1185EB, 0x4F7C7B57, 0xCFBFA1C8, 0xC2B3293D  \
};


void linear_layer(state_t *state, int nb)
{
  int i, b = nb/2;
  uint32_t *x = state->x, *y = state->y;
  uint32_t tmp;

  // Feistel function (adding to y part)
  tmp = 0;
  for(i = 0; i < b; i ++)
    tmp ^= x[i];
  tmp = ELL(tmp);
  for(i = 0; i < b; i ++)
    y[i+b] ^= (tmp ^ y[i]);

  // Feistel function (adding to x part)
  tmp = 0;
  for(i = 0; i < b; i ++)
    tmp ^= y[i];
  tmp = ELL(tmp);
  for(i = 0; i < b; i ++)
    x[i+b] ^= (tmp ^ x[i]);

  // Branch swap with 1-branch left-rotation of right side
  // <------- left side --------> <------- right side ------->
  //    0    1    2 ...  B-2  B-1    B  B+1  B+2 ... 2B-2 2B-1
  //  B+1  B+2  B+3 ... 2B-1    B    0    1    2 ...  B-2  B-1

  // Branch swap of the x part
  tmp = x[0];
  for (i = 0; i < b-1; i ++) {
    x[i] = x[i+b+1];
    x[i+b+1] = x[i+1];
  }
  x[b-1] = x[b];
  x[b] = tmp;

  // Branch swap of the y part
  tmp = y[0];
  for (i = 0; i < b-1; i ++) {
    y[i] = y[i+b+1];
    y[i+b+1] = y[i+1];
  }
  y[b-1] = y[b];
  y[b] = tmp;
}


void sparkle_ref(state_t *state, int nb, int ns)
{
  int i, j;  // Step and branch counter

  // The number of branches (nb) must be even and not bigger than MAX_BRANCHES.
  assert(((nb & 1) == 0) && (nb >= 4) && (nb <= MAX_BRANCHES));

  for(i = 0; i < ns; i ++) {
    // Add step counter
    state->y[0] ^= RCON[i%MAX_BRANCHES];
    state->y[1] ^= i;
    // ARXBox layer
    for(j = 0; j < nb; j ++)
      ARXBOX(state->x[j], state->y[j], RCON[j]);
    // Linear layer
    linear_layer(state, nb);
  }
}


void linear_layer_inv(state_t *state, int nb)
{
  int i, b = nb/2;
  uint32_t *x = state->x, *y = state->y;
  uint32_t tmp;

  // Branch swap with 1-branch right-rotation of left side
  // <------- left side --------> <------- right side ------->
  //    0    1    2 ...  B-2  B-1    B  B+1  B+2 ... 2B-2 2B-1
  //    B  B+1  B+2 ... 2B-2 2B-1  B-1    0    1 ...  B-3  B-2

  // Branch swap of the x part
  tmp = x[b-1];
  for (i = b-1; i > 0; i --) {
    x[i] = x[i+b];
    x[i+b] = x[i-1];
  }
  x[0] = x[b];
  x[b] = tmp;

  // Branch swap of the y part
  tmp = y[b-1];
  for (i = b-1; i > 0; i --) {
    y[i] = y[i+b];
    y[i+b] = y[i-1];
  }
  y[0] = y[b];
  y[b] = tmp;

  // Feistel function (adding to x part)
  tmp = 0;
  for(i = 0; i < b; i ++)
    tmp ^= y[i];
  tmp = ELL(tmp);
  for(i = 0; i < b; i ++)
    x[i+b] ^= (tmp ^ x[i]);

  // Feistel function (adding to y part)
  tmp = 0;
  for(i = 0; i < b; i ++)
    tmp ^= x[i];
  tmp = ELL(tmp);
  for(i = 0; i < b; i ++)
    y[i+b] ^= (tmp ^ y[i]);
}


void sparkle_inv_ref(state_t *state, int nb, int ns)
{
  int i, j;  // Step and branch counter

  // The number of branches (nb) must be even and not bigger than MAX_BRANCHES.
  assert(((nb & 1) == 0) && (nb >= 4) && (nb <= MAX_BRANCHES));

  for(i = ns-1; i >= 0; i --) {
    // Linear layer
    linear_layer_inv(state, nb);
    // ARXbox layer
    for(j = 0; j < nb; j ++)
      ARXBOX_INV(state->x[j], state->y[j], RCON[j]);
    // Add step counter
    state->y[1] ^= i;
    state->y[0] ^= RCON[i%MAX_BRANCHES];
  }
}


void print_state_ref(const state_t *state, int nb)
{
  uint8_t *xbytes = (uint8_t *) state->x;
  uint8_t *ybytes = (uint8_t *) state->y;
  int i, j;

  for (i = 0; i < nb; i ++) {
    j = 4*i;
    printf("(%02x%02x%02x%02x %02x%02x%02x%02x)",     \
    xbytes[j], xbytes[j+1], xbytes[j+2], xbytes[j+3], \
    ybytes[j], ybytes[j+1], ybytes[j+2], ybytes[j+3]);
    if (i < nb-1) printf(" ");
  }
  printf("\n");
}


void test_sparkle_ref(int nb, int ns)
{
  state_t state = {{0}, {0}};

  printf("input:\n");
  print_state_ref(&state, nb);
  sparkle_ref(&state, nb, ns);
  printf("sparkle:\n");
  print_state_ref(&state, nb);
  sparkle_inv_ref(&state, nb, ns);
  printf("sparkle inv:\n");
  print_state_ref(&state, nb);
  printf("\n");
}
