///////////////////////////////////////////////////////////////////////////////
// schwaemm_cfg.h: Configuration of instances of AEAD algorithm SCHWAEMM.    //
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


#ifndef SCHWAEMM_CFG_H
#define SCHWAEMM_CFG_H

// Define the SCHWAEMM instance here (api.h has to match!). The main instance
// is SCHWAEMM256_128, which has a block size of 256 bits and a key size of 128
// bits. Other instances of SCHWAEMM are SCHWAEMM128_128, SCHWAEMM192_192, and
// SCHWAEMM256_256.

#define SCHWAEMM256_128

// The identifier SPARKLE_ASSEMBLER determines whether the low-level functions 
// in encrypt.c use the C implementation or an assembler implementation of the
// SPARKLE permutation. Currently, assembler code for SPARKLE exists for the
// AVR and ARM architecture.

#define SPARKLE_ASSEMBLER


///////////////////////////
#if defined SCHWAEMM128_128
///////////////////////////

#define SCHWAEMM_KEY_LEN    128
#define SCHWAEMM_NONCE_LEN  128
#define SCHWAEMM_TAG_LEN    128

#define SPARKLE_STATE       256
#define SPARKLE_RATE        128
#define SPARKLE_CAPACITY    128

#define SPARKLE_STEPS_SLIM  7
#define SPARKLE_STEPS_BIG   10


/////////////////////////////
#elif defined SCHWAEMM256_128
/////////////////////////////

#define SCHWAEMM_KEY_LEN    128
#define SCHWAEMM_NONCE_LEN  256
#define SCHWAEMM_TAG_LEN    128

#define SPARKLE_STATE       384
#define SPARKLE_RATE        256
#define SPARKLE_CAPACITY    128

#define SPARKLE_STEPS_SLIM  7
#define SPARKLE_STEPS_BIG   11


/////////////////////////////
#elif defined SCHWAEMM192_192
/////////////////////////////

#define SCHWAEMM_KEY_LEN    192
#define SCHWAEMM_NONCE_LEN  192
#define SCHWAEMM_TAG_LEN    192

#define SPARKLE_STATE       384
#define SPARKLE_RATE        192
#define SPARKLE_CAPACITY    192

#define SPARKLE_STEPS_SLIM  7
#define SPARKLE_STEPS_BIG   11


/////////////////////////////
#elif defined SCHWAEMM256_256
/////////////////////////////

#define SCHWAEMM_KEY_LEN    256
#define SCHWAEMM_NONCE_LEN  256
#define SCHWAEMM_TAG_LEN    256

#define SPARKLE_STATE       512
#define SPARKLE_RATE        256
#define SPARKLE_CAPACITY    256

#define SPARKLE_STEPS_SLIM  8
#define SPARKLE_STEPS_BIG   12


#else
#error "Invalid definition of SCHWAEMM instance!"
#endif

#endif  // SCHWAEMM_CFG_H
