///////////////////////////////////////////////////////////////////////////////
// Util.h: C implementation of the SCHWAEMM AEAD algorithm, auxiliary file   //
// This file is part of the NIST's submission "Schwaemm and Esch: Lightweight//
// Authenticated Encryption and Hashing using the Sparkle Permutation Family //
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
#ifndef UTIL_H
#define UTIL_H

#include "stdint.h"
#include "schwaemmconfig.h"

#ifdef _DEBUG
    #define INLINE
#else
    #define INLINE inline
#endif /*_DEBUG*/

#define u8 unsigned char
#define u64 long long unsigned int

#define WORDSIZE (32)
#define BYTE(X) (X/8)
#define WORD(X) (X/WORDSIZE)
#define ROT32(x, n) ((x >> n) | (x << (WORDSIZE-n)))
#define INJECTCONST(x, y) x[WORD(STATESIZE)-1] ^= (y) << 24

#define SWAPu32(X, Y, TMP) {TMP = X; X=Y; Y=TMP;}

#define RATEWHITENING(S) do{                          \
    for(int _i=0; _i<WORD(RATE); _i++){               \
        S[_i] ^= S[(WORD(RATE))+(_i%(WORD(CAPACITY)))];   \
    }                                                 \
}while(0)

/*subfunction used on the linear_layer of SPARKLE*/
#define ELL(x) do{                                                             \
    x ^= x << 16;                                                              \
    x = ROT32(x, 16);                                                          \
}while(0)

extern const uint32_t C_SEED[8];

uint32_t load32( unsigned char *in);
    void store32(unsigned char *out, uint32_t in);
    void feistelSwap(uint32_t *state);
    void rho1(uint32_t *state, uint32_t *D);
    void rho2(uint32_t *state, uint32_t *D);
    void rhop1(uint32_t *state, uint32_t *D);
    void pad(uint32_t *out, u8 *in, u8 inlen);
    void sparklePermutation(uint32_t state[WORD(STATESIZE)], int Ns);

#endif /*UTIL_H*/
