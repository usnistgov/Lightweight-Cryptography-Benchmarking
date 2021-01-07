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

#include "data_types.h"
#include "constants.h"
#include "aes_gmul_o.h"

extern DATA_SBOX_BYTE sbox[256];


#define GF256MUL_1(a) (a)
#define GF256MUL_2(a) (aes_gmul_o(2, (a)))
#define GF256MUL_3(a) (aes_gmul_o(3, (a)))


void aes_shiftcol(uint8_t *data, uint8_t shift) {
    uint8_t tmp[4];


    tmp[0] = data[0];
    tmp[1] = data[4];
    tmp[2] = data[8];
    tmp[3] = data[12];

    data[0] = tmp[(shift + 0) & 3];
    data[4] = tmp[(shift + 1) & 3];
    data[8] = tmp[(shift + 2) & 3];
    data[12] = tmp[(shift + 3) & 3];
}

static void aes_enc_round(uint8_t *block, uint8_t *round_key) {
    uint8_t tmp[16], t;
    uint8_t i;


    /* subBytes */
    for (i = 0; i < 16; ++i) {
        tmp[i] = READ_SBOX_BYTE(sbox[block[i]]);
    }

    /* shiftRows */
    aes_shiftcol(tmp + 1, 1);
    aes_shiftcol(tmp + 2, 2);
    aes_shiftcol(tmp + 3, 3);

    /* mixColums */
    for (i = 0; i < 4; ++i) {
        t = tmp[4 * i + 0] ^ tmp[4 * i + 1] ^ tmp[4 * i + 2] ^ tmp[4 * i + 3];

        block[4 * i + 0] = GF256MUL_2(tmp[4 * i + 0] ^ tmp[4 * i + 1])
                ^ tmp[4 * i + 0]
                ^ t;

        block[4 * i + 1] = GF256MUL_2(tmp[4 * i + 1] ^ tmp[4 * i + 2])
                ^ tmp[4 * i + 1]
                ^ t;

        block[4 * i + 2] = GF256MUL_2(tmp[4 * i + 2] ^ tmp[4 * i + 3])
                ^ tmp[4 * i + 2]
                ^ t;

        block[4 * i + 3] = GF256MUL_2(tmp[4 * i + 3] ^ tmp[4 * i + 0])
                ^ tmp[4 * i + 3]
                ^ t;
    }

    /* addKey */
    for (i = 0; i < 16; ++i) {
        block[i] ^= round_key[i];
    }
}

void aes_enc_lastround(uint8_t *block, uint8_t *round_key) {
    uint8_t i;


    /* subBytes */
    for (i = 0; i < 16; ++i) {
        block[i] = READ_SBOX_BYTE(sbox[block[i]]);
    }

    /* shiftRows */
    aes_shiftcol(block + 1, 1);
    aes_shiftcol(block + 2, 2);
    aes_shiftcol(block + 3, 3);

    /* keyAdd */
    for (i = 0; i < 16; ++i) {
        block[i] ^= round_key[i];
    }
}

// By CC
// Changed function name to aes_encrypt2 due to a naming conflict with Espressif library
void aes_encrypt2(uint8_t *block, uint8_t *round_keys) {
    uint8_t i;


    for (i = 0; i < 16; ++i) {
        block[i] ^= round_keys[i];
    }

    for (i = 1; i < 10; ++i) {
        aes_enc_round(block, round_keys + 16 * i);
    }

    aes_enc_lastround(block, round_keys + 16 * 10);
}
