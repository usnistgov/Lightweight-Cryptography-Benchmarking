/*
 * SKINNY Block Cipher Reference C Implementation
 * 
 * Copyright 2018:
 *     Jeremy Jean for the SKINNY Team
 *     https://sites.google.com/site/skinnycipher/
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 * 
 */

#include <stdint.h>

/*
** Encryption and decryption functions for all the TBC in the SKINNY family 
** The version parameter "ver" selects the TBC of the family according to:
** 		0: SKINNY-64-64 (32 rounds)
** 		1: SKINNY-64-128 (36 rounds)
** 		2: SKINNY-64-192 (40 rounds)
** 		3: SKINNY-128-128 (40 rounds)
** 		4: SKINNY-128-256 (48 rounds)
** 		5: SKINNY-128-384 (56 rounds)
};
*/
void enc(const uint8_t* input, const uint8_t* tweakey, uint8_t* output, const int ver);
void dec(const uint8_t* input, const uint8_t* tweakey, uint8_t* output, const int ver);
