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

#include "cipher.h"
#include "data_types.h"
#include "constants.h"
#include "aes.h"
#include "hash.h"
#include "mul_h.h"

void TagGeneration(uint8_t *state, uint8_t *tag) {
    /* hash ciphertext + padding + len(aad_len) + len(p_len) */
    uint8_t t[16];
    uint8_t j;
    gcm_state_t *gcm_state;

    /* hash a_len and p_len (beware of endianness conversion required!) */
    gcm_state = (gcm_state_t *) state;
    t[15] = (gcm_state->msg_len << 3) & 0xff;
    t[14] = ((gcm_state->msg_len << 3) >> 8) & 0xff;
    t[13] = 0x00;
    t[12] = 0x00;
    t[11] = 0x00;
    t[10] = 0x00;
    t[9] = 0x00;
    t[8] = 0x00;
    t[7] = (gcm_state->aad_len << 3) & 0xff;
    t[6] = ((gcm_state->aad_len << 3) >> 8) & 0xff;
    t[5] = 0x00;
    t[4] = 0x00;
    t[3] = 0x00;
    t[2] = 0x00;
    t[1] = 0x00;
    t[0] = 0x00;
    for (j = 0; j < 16; j++) {
        t[j] = gcm_state->tag_state[j] ^ t[j];
    }
    mul_h(gcm_state->H, t, tag);

    /* authenticate */
    // By CC - updated function name aes_encrypt()
    aes_encrypt2(gcm_state->icb, gcm_state->round_keys);
    for (j = 0; j < 16; j++) {
        tag[j] = gcm_state->icb[j] ^ tag[j];
    }
}
