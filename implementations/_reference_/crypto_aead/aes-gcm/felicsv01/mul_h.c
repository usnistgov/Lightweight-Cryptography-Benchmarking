/*
 *
 * University of Luxembourg
 * Laboratory of Algorithmics, Cryptology and Security (LACS)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2017 University of Luxembourg
 *
 * Written in 2017 by Virat Shejwalkar <virat.shejwalkar@uni.lu>
 *
 * This file is part of FELICS.
 *
 * FELICS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * FELICS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdint.h>
#include <stdio.h>

#include "data_types.h"

void shr1(uint8_t v[16]) {
    uint8_t byte_idx;
    uint8_t msb_in;
    uint8_t lsb_out;

    msb_in = 0;
    for (byte_idx = 0; byte_idx < 16; byte_idx++) {
        lsb_out = v[byte_idx] & 0x01;
        v[byte_idx] = (v[byte_idx] >> 1) | msb_in;
        msb_in = lsb_out << 7;
    }
}

void mul_h(uint8_t h[16], uint8_t x[16], uint8_t z[16]) {
    uint8_t v[16];
    uint8_t xi;
    uint8_t lsb;
    uint8_t bit_idx;
    uint8_t byte_idx;
    uint8_t i;
    uint8_t j;

    const uint8_t R = 0xe1;

    for (i = 0; i < 16; i++) {
        v[i] = h[i];
        z[i] = 0;
    }
    for (i = 0; i < 128; i++) {
        byte_idx = i >> 3;
        bit_idx = 7 - (i & 0x07);
        xi = (x[byte_idx] >> bit_idx) & 0x01;
        for (j = 0; j < 16; j++) {
#if defined(MSP)
            /* MSP gcc is dumb */
            xi = (xi << 1) | xi;
            xi = (xi << 2) | xi;
            xi = (xi << 4) | xi;
            z[j] ^= (v[j] & xi);
#else
            z[j] ^= (v[j] * xi);
#endif
        }
        lsb = v[15] & 0x01;
        shr1(v);
#if defined(MSP)
        /* MSP gcc is dumb */
        lsb = (lsb << 1) | lsb;
        lsb = (lsb << 2) | lsb;
        lsb = (lsb << 4) | lsb;
        v[0] ^= (R & lsb);
#else
        v[0] ^= (R * lsb);
#endif
    }
}
