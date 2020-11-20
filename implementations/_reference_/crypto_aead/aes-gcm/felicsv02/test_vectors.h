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

#ifndef TEST_VECTORS_H
#define TEST_VECTORS_H

#include "constants.h"


/*
 *
 * Test vectors
 *
 */
extern const uint8_t expectedKey[KEY_SIZE]; /* Key value */
extern const uint8_t expectedNonce[NONCE_SIZE]; /* Nonce value */
extern const uint8_t expectedAssociatedData[TEST_ASSOCIATED_DATA_SIZE]; /* Associated data input value */

extern const uint8_t expectedTag[TAG_SIZE]; /* Tag value after encryption/decryption */


/* Encryption phases expected state values */
extern const uint8_t expectedPostInitializationState[STATE_SIZE];   /* State value after initialization */
extern const uint8_t expectedPostAssociatedDataProcessingState[STATE_SIZE]; /* State value after processing of associated data */
extern const uint8_t expectedPostPlaintextProcessingState[STATE_SIZE];  /* State value after processing of plaintext */
extern const uint8_t expectedPostFinalizationState[STATE_SIZE]; /* State value after finalization phase */
extern const uint8_t expectedCiphertext[TEST_MESSAGE_SIZE]; /* Ciphertext value after encryption */


/* Decryption phases state values */
extern const uint8_t expectedPlaintext[TEST_MESSAGE_SIZE];  /* Plaintext value after decryption */

#endif /* TEST_VECTORS_H */
