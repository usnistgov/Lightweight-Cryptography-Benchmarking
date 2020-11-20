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
#include "mul_h.h"

// By CC - added const qualifier to data
void hash(gcm_state_t * gcm_state, const uint8_t *data, uint16_t len) {
    uint8_t w;
    uint8_t t[16];
    uint8_t j;
    uint16_t i;

    for (i = 0; i < len; i += 16) {
        for (j = 0; j < 16; j++) {
            if ((i + j) < len) {
                w = data[i + j];
            } else {
                w = 0x00;
            }
            t[j] = gcm_state->tag_state[j] ^ w;
        }
        mul_h(gcm_state->H, t, gcm_state->tag_state);
    }
}
