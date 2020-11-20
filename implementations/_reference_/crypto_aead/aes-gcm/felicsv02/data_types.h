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

#ifndef DATA_TYPES_H
#define DATA_TYPES_H

#include "cipher.h"



/*
 *
 * Implementation data types
 *
 */
#define DATA_SBOX_BYTE RAM_DATA_BYTE
#define READ_SBOX_BYTE READ_RAM_DATA_BYTE

#define DATA_KS_BYTE RAM_DATA_BYTE
#define READ_KS_BYTE READ_RAM_DATA_BYTE


/* Our state structure */
typedef struct {
    uint8_t round_keys[176];    /* AES round keys */
    uint8_t H[16];  /* H */
    uint8_t tag_state[16];  /* tag state */
    uint8_t icb[16];    /* initial counter block = IV || 000..01 */
    uint16_t msg_len;   /* message length */
    uint16_t aad_len;   /* addition authenticated data length */
} gcm_state_t;


#endif /* DATA_TYPES_H */
