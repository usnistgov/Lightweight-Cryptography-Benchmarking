///////////////////////////////////////////////////////////////////////////////
// sparkle_opt.h: Optimized C99 implementation of the SPARKLE permutation.   //
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

#ifndef SPARKLE_OPT_H
#define SPARKLE_OPT_H

#if defined(_MSC_VER) && !defined(__clang__) && !defined(__ICL)
typedef unsigned __int8 uint8_t;
typedef unsigned __int32 uint32_t;
#else
#include <stdint.h>
#endif  // _MSC_VER

#define MAX_BRANCHES 8

void sparkle_opt(uint32_t *state, int brans, int steps);
void sparkle_inv_opt(uint32_t *state, int brans, int steps);

void clear_state_opt(uint32_t *state, int brans);
void print_state_opt(const uint32_t *state, int brans);
void test_sparkle_opt(int brans, int steps);

#endif  // SPARKLE_OPT_H
