///////////////////////////////////////////////////////////////////////////////
// sparkle_opt.c: Optimized C implementation of the SPARKLE permutation.     //
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

#include <stdio.h>
#include "sparkle_opt.h"

#define ROT(x, n) (((x) >> (n)) | ((x) << (32-(n))))
#define ELL(x) (ROT((x), 16) ^ ((x) & MASK16))

static const uint32_t MASK16 = 0xFFFFU;

// Round constants
static const uint32_t RCON[MAX_BRANCHES] = {      \
  0xB7E15162, 0xBF715880, 0x38B4DA56, 0x324E7738, \
  0xBB1185EB, 0x4F7C7B57, 0xCFBFA1C8, 0xC2B3293D  \
};


void sparkle_opt(uint32_t *state, int nb, int ns)
{
  int i, j;  // Step and branch counter
  uint32_t rc, tmpx, tmpy, x0, y0;

  for(i = 0; i < ns; i ++) {
    // Add step counter
    state[1] ^= RCON[i%MAX_BRANCHES];
    state[3] ^= i;
    // ARXBox layer
    for(j = 0; j < 2*nb; j += 2) {
      rc = RCON[j>>1];
      state[j] += ROT(state[j+1], 31);
      state[j+1] ^= ROT(state[j], 24);
      state[j] ^= rc;
      state[j] += ROT(state[j+1], 17);
      state[j+1] ^= ROT(state[j], 17);
      state[j] ^= rc;
      state[j] += state[j+1];
      state[j+1] ^= ROT(state[j], 31);
      state[j] ^= rc;
      state[j] += ROT(state[j+1], 24);
      state[j+1] ^= ROT(state[j], 16);
      state[j] ^= rc;
    }
    // Linear layer
    tmpx = x0 = state[0];
    tmpy = y0 = state[1];
    for(j = 2; j < nb; j += 2) {
      tmpx ^= state[j];
      tmpy ^= state[j+1];
    }
    tmpx = ELL(tmpx);
    tmpy = ELL(tmpy);
    for (j = 2; j < nb; j += 2) {
      state[j-2] = state[j+nb] ^ state[j] ^ tmpy;
      state[j+nb] = state[j];
      state[j-1] = state[j+nb+1] ^ state[j+1] ^ tmpx;
      state[j+nb+1] = state[j+1];
    }
    state[nb-2] = state[nb] ^ x0 ^ tmpy;
    state[nb] = x0;
    state[nb-1] = state[nb+1] ^ y0 ^ tmpx;
    state[nb+1] = y0;
  }
}


void sparkle_inv_opt(uint32_t *state, int nb, int ns)
{
  int i, j;  // Step and branch counter
  uint32_t rc, tmpx, tmpy, xb1, yb1;

  for(i = ns-1; i >= 0; i --) {
    // Linear layer
    tmpx = tmpy = 0;
    xb1 = state[nb-2];
    yb1 = state[nb-1];
    for (j = nb-2; j > 0; j -= 2) {
      tmpx ^= (state[j] = state[j+nb]);
      state[j+nb] = state[j-2];
      tmpy ^= (state[j+1] = state[j+nb+1]);
      state[j+nb+1] = state[j-1];
    }
    tmpx ^= (state[0] = state[nb]);
    state[nb] = xb1;
    tmpy ^= (state[1] = state[nb+1]);
    state[nb+1] = yb1;
    tmpx = ELL(tmpx);
    tmpy = ELL(tmpy);
    for(j = nb-2; j >= 0; j -= 2) {
      state[j+nb] ^= (tmpy ^ state[j]);
      state[j+nb+1] ^= (tmpx ^ state[j+1]);
    }
    // ARXBox layer
    for(j = 0; j < 2*nb; j += 2) {
      rc = RCON[j>>1];
      state[j] ^= rc;
      state[j+1] ^= ROT(state[j], 16);
      state[j] -= ROT(state[j+1], 24);
      state[j] ^= rc;
      state[j+1] ^= ROT(state[j], 31);
      state[j] -= state[j+1];
      state[j] ^= rc;
      state[j+1] ^= ROT(state[j], 17);
      state[j] -= ROT(state[j+1], 17);
      state[j] ^= rc;
      state[j+1] ^= ROT(state[j], 24);
      state[j] -= ROT(state[j+1], 31);
    }
    // Add step counter
    state[1] ^= RCON[i%MAX_BRANCHES];
    state[3] ^= i;
  }
}


void print_state_opt(const uint32_t *state, int nb)
{
  uint8_t *xybytes = (uint8_t *) state;
  int i, j;

  for (i = 0; i < nb; i ++) {
    j = 8*i;
    printf("(%02x%02x%02x%02x %02x%02x%02x%02x)",           \
    xybytes[j],   xybytes[j+1], xybytes[j+2], xybytes[j+3], \
    xybytes[j+4], xybytes[j+5], xybytes[j+6], xybytes[j+7]);
    if (i < nb-1) printf(" ");
  }
  printf("\n");
}


void test_sparkle_opt(int nb, int ns)
{
  uint32_t state[2*MAX_BRANCHES] = { 0 };

  printf("input:\n");
  print_state_opt(state, nb);
  sparkle_opt(state, nb, ns);
  printf("sparkle:\n");
  print_state_opt(state, nb);
  sparkle_inv_opt(state, nb, ns);
  printf("sparkle inv:\n");
  print_state_opt(state, nb);
  printf("\n");
}
