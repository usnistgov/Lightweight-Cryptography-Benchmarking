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

void Initialize(uint8_t *state, const uint8_t *key, const uint8_t *nonce) {
    /* aes key schedule + computation of H + computation of icb */
    uint8_t i;
    gcm_state_t *gcm_state;

    gcm_state = (gcm_state_t *) state;
    aes_key_schedule(key, gcm_state->round_keys);
    for (i = 0; i < 16; i++) {
        gcm_state->H[i] = 0;
    }
    // By CC - updated function name aes_encrypt()
    aes_encrypt2(gcm_state->H, gcm_state->round_keys);

    gcm_state->icb[0] = nonce[0];
    gcm_state->icb[1] = nonce[1];
    gcm_state->icb[2] = nonce[2];
    gcm_state->icb[3] = nonce[3];
    gcm_state->icb[4] = nonce[4];
    gcm_state->icb[5] = nonce[5];
    gcm_state->icb[6] = nonce[6];
    gcm_state->icb[7] = nonce[7];
    gcm_state->icb[8] = nonce[8];
    gcm_state->icb[9] = nonce[9];
    gcm_state->icb[10] = nonce[10];
    gcm_state->icb[11] = nonce[11];
    gcm_state->icb[12] = 0x00;
    gcm_state->icb[13] = 0x00;
    gcm_state->icb[14] = 0x00;
    gcm_state->icb[15] = 0x01;
}
