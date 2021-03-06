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

#include "data_types.h"
#include "aes.h"

void encrypt_message(gcm_state_t * gcm_state, uint8_t *message, uint16_t len) {
    uint8_t cb[16];
    uint8_t aes_state[16];
    uint8_t n_xor;
    uint8_t i;
    int16_t remaining_bytes;
    uint32_t counter;
    uint8_t *current_block;

    for (i = 0; i < 16; i++) {
        cb[i] = gcm_state->icb[i];
    }
    remaining_bytes = len;
    current_block = message;
    for (remaining_bytes = len; remaining_bytes > 0; remaining_bytes -= 16) {
        counter =
                ((uint32_t)cb[12] << 24) | ((uint32_t)cb[13] << 16) |
                ((uint32_t)cb[14] << 8) | cb[15];
        counter++;
        cb[12] = (counter >> 24) & 0xff;
        cb[13] = (counter >> 16) & 0xff;
        cb[14] = (counter >> 8) & 0xff;
        cb[15] = counter & 0xff;
        for (i = 0; i < 16; i++) {
            aes_state[i] = cb[i];
        }
        // By CC - updated function name aes_encrypt()
        aes_encrypt2(aes_state, gcm_state->round_keys);
        n_xor = (remaining_bytes < 16) ? remaining_bytes : 16;
        for (i = 0; i < n_xor; i++) {
            current_block[i] ^= aes_state[i];
        }
        current_block += 16;
    }
}
