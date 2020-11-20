/*
 *
 * University of Luxembourg
 * Laboratory of Algorithmics, Cryptology and Security (LACS)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2015 University of Luxembourg
 *
 * Written in 2015 by Dmitry Khovratovich <dmitry.khovratovich@uni.lu>
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

/*
 * This file is part of the AVR-Crypto-Lib.
 * Copyright (C) 2008, 2009  Daniel Otte (daniel.otte@rub.de)
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdint.h>
#include <string.h>

#include "data_types.h"
#include "constants.h"

extern DATA_SBOX_BYTE sbox[256];
extern DATA_KS_BYTE rc_tab[10];


void aes_rotword(uint8_t *a) {
    uint8_t t;


    t = a[0];
    a[0] = a[1];
    a[1] = a[2];
    a[2] = a[3];
    a[3] = t;
}


void aes_key_schedule(uint8_t *key, uint8_t *round_keys) {
    uint8_t i;
    uint8_t rc = 0;

    union {
        uint32_t v32;
        uint8_t v8[4];
    } tmp;


    memcpy(round_keys, key, 16);

    for (i = 4; i < 44; ++i) {
        tmp.v32 = ((uint32_t *)(round_keys))[i - 1];
        if (0 == i % 4) {
            aes_rotword((uint8_t *)&(tmp.v32));

            tmp.v8[0] = READ_SBOX_BYTE(sbox[tmp.v8[0]]);
            tmp.v8[1] = READ_SBOX_BYTE(sbox[tmp.v8[1]]);
            tmp.v8[2] = READ_SBOX_BYTE(sbox[tmp.v8[2]]);
            tmp.v8[3] = READ_SBOX_BYTE(sbox[tmp.v8[3]]);
            tmp.v8[0] ^= READ_KS_BYTE(rc_tab[rc]);
            rc++;
        }
        ((uint32_t *)(round_keys))[i] = ((uint32_t *)(round_keys))[i - 4]
                ^ tmp.v32;
    }
}
