///////////////////////////////////////////////////////////////////////////////
// eschconfig.h: Configuration of two instances of the hash function ESCH.   //
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

#ifndef _ESCHCONFIG_H
#define _ESCHCONFIG_H

// Define the ESCH instance here (api.h has to match!).

#define ESCH384

// Some common definitions for all instances of ESCH:

// Each message block has a byte-length of 16 bytes
#define MSGBLOCK_BLEN 16
// Each message block has a word-length of 4 words
#define MSGBLOCK_WLEN (MSGBLOCK_BLEN/4)
// Each squeeze block has a byte-length of 16 bytes
#define SQZBLOCK_BLEN 16
// Each squeeze block has a word-length of 4 words
#define SQZBLOCK_WLEN (SQZBLOCK_BLEN/4)

#if defined ESCH256
// ESCH256 uses SPARKLE384, which has 6 branches
#define NUM_BRANCHES 6
// The number of slim steps of ESCH256 is 7
#define STEPS_SLIM 7
// The number of big steps of ESCH256 is 11
#define STEPS_BIG 11

#elif defined ESCH384
// ESCH384 uses SPARKLE512, which has 8 branches
#define NUM_BRANCHES 8
// The number of slim steps of ESCH384 is 8
#define STEPS_SLIM 8
// The number of big steps of ESCH384 is 12
#define STEPS_BIG 12

#else
#error "Invalid definition of ESCH instance."
#endif

#endif  // _ESCHCONFIG_H
