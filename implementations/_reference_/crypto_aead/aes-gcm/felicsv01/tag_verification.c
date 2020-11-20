/*
 *
 * University of Luxembourg
 * Laboratory of Algorithmics, Cryptology and Security (LACS)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2015-2019 University of Luxembourg
 *
 * Author: Luan Cardoso (2019), Virat Shejwalkar (2017),
 *         Daniel Dinu (2015), and Yann Le Corre (2015)
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
#include "constants.h"


/*
 *
 * Verify if an authentication tag is valid. Used only during decryption phase
 * ... state - the state of the cipher
 * ... tag - the tag to verify
 *
 * The function will return:
 *      0 - if tag matches
 *     -1 - if tag does not match
 *
 */
int TagVerification(uint8_t *state, uint8_t *tag) {
    RAM_DATA_BYTE generated_tag[TAG_SIZE];
    uint8_t correct = 0;
    uint8_t i;

    TagGeneration(state, generated_tag);

    for (i = 0; i < TAG_SIZE; i++) {
        if (generated_tag[i] != tag[i]) {
            correct = -1;
        }
    }

    return correct;
}
