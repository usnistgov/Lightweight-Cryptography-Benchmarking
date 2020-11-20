///////////////////////////////////////////////////////////////////////////////
// Util.c: C implementation of the SCHWAEMM AEAD algorithm, auxiliary file   //
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
#include "stdint.h"
#include "util.h"
#include "schwaemmconfig.h"
#include "string.h"
#include "sparkle_ref.h"

const uint32_t C_SEED[8] = {0xB7E15162, 0x8AED2A6A, 0xBF715880, 0x9CF4F3C7, 0x62E7160F, 0x38B4DA56, 0xA784D904, 0x5190CFEF};

uint32_t load32( unsigned char *in){
    uint32_t out;
    memcpy (&out, in, sizeof(out));
    return out;
}

void store32(unsigned char *out, uint32_t in){
     memcpy (out, &in, sizeof(in));
}

void feistelSwap(uint32_t *state){
    //feistelSwap works on the rate part of the state, and is defined as
    // S1 || S2 = S2 ||(S2 \xor S1), with S1 and S2 being equal halfs of the rate.
    uint32_t tmp;
    for(int i=0; i<WORD(RATE/2); i++){
        tmp = state[i];
        state[i] = state[WORD(RATE/2)+i];
        state[WORD(RATE/2)+i] ^= tmp;
    }
}

void rho1(uint32_t *state, uint32_t *D){
    feistelSwap(state);
    for(int i=0; i<WORD(RATE); i++)
        state[i] ^= D[i];
}

void rho2(uint32_t *state, uint32_t *D){ /*rho2 is equal to rho'2*/
    for(int i=0; i<WORD(RATE); i++)
        state[i] ^= D[i];
}

void rhop1(uint32_t *state, uint32_t *D){ /*rho prime*/
    uint32_t tmp[BYTE(RATE)];
    memcpy (tmp, state, BYTE(RATE));
    feistelSwap(state);
    for(int i=0; i<WORD(RATE); i++)
        state[i] ^= D[i] ^ tmp[i];
}


void pad(uint32_t *out, u8 *in, u8 inlen){
    //If the padding isn't necessary, then only copy.
    memcpy(out, in, inlen);
    uint8_t *o;
    o=(uint8_t *)(out);
    if (inlen!=BYTE(RATE)){
        o[inlen]=0x80;
        memset(o+inlen+1, 0, BYTE(RATE)-inlen-1);
    }
}
//wrapper funcion for the permutation
void sparklePermutation(uint32_t state[WORD(STATESIZE)], int Ns){
    state_t S={{0},{0}};
    for (int i=0; i<B*2; i++){
        S.x[i] = state[2*i];
        S.y[i] = state[2*i+1];
    }

    sparkle_ref(&S, B*2, Ns); //Number of 32-bit branches, hence B*4

    for (int i=0; i<B*2; i++){
        state[2*i]   = S.x[i];
        state[2*i+1] = S.y[i];
    }

}
