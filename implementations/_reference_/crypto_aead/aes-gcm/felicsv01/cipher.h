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

#ifndef CIPHER_H
#define CIPHER_H


#include<stdint.h>

// By CC
#if (defined(LWC_PLATFORM_MKRZERO) || defined(LWC_PLATFORM_NANO33BLE)) && !defined(ARM)
#define ARM
#elif (defined(LWC_PLATFORM_UNO) || defined(LWC_PLATFORM_NANOEVERY)) && !defined(AVR)
#define AVR
#endif
// End - CC

#ifdef AVR                      /* AVR */
#include <avr/pgmspace.h>
#endif /* AVR */

/*
 *
 * Definitions of TRUE and FALSE used for skip state check macros
 *
 */
#define SKIP_STATE_CHECK_TRUE 1
#define SKIP_STATE_CHECK_FALSE 0

/*
 *
 * Optimization levels
 * ... OPTIMIZATION_LEVEL_0 - O0
 * ... OPTIMIZATION_LEVEL_1 - O1
 * ... OPTIMIZATION_LEVEL_2 - O2
 * ... OPTIMIZATION_LEVEL_3 - O3 = defualt
 *
 */
#define OPTIMIZATION_LEVEL_0 __attribute__((optimize("O0")))
#define OPTIMIZATION_LEVEL_1 __attribute__((optimize("O1")))
#define OPTIMIZATION_LEVEL_2 __attribute__((optimize("O2")))
#define OPTIMIZATION_LEVEL_3 __attribute__((optimize("O3")))


/*
 *
 * SCENARIO values:
 * ... SCENARIO_0 0 - Test scenario, operating over a single block of input
 Scenarios 1, 2, and 3 are based on the specifications of 6LoWPAN (RFC 6282 RFC 4944)
 * ... SCENARIO_1 1 - Encrypt only of 102 bytes
 * ... SCENARIO_2 2 - Authenticate only 86 bytes of plaintext + 25bytes header
 * ... SCENARIO_3 3 - Encrypt and Authenticate 86 bytes of plaintex + 25 bytes header
 Scenarios 4, 5 and 6 are based on the use cases of IPv6 (RFC 2460)
 * ... SCENARIO_4 4 - Encrypt only of 1240 bytes
 * ... SCENARIO_5 5 - Authenticate only 1224 bytes of plaintext + 40 bytes of header
 * ... SCENARIO_6 6 - Encrypt and Authenticate 1224 bytes of plaintext + 40 bytes header
 *
 */
#define SCENARIO_0 0
#define SCENARIO_1 1
#define SCENARIO_2 2
#define SCENARIO_3 3
#define SCENARIO_4 4
#define SCENARIO_5 5
#define SCENARIO_6 6

#ifndef SCENARIO
#define SCENARIO SCENARIO_0
#endif

/* Scenario 0 data */
#if defined(SCENARIO) && (SCENARIO_0 == SCENARIO)
#define MESSAGE_SIZE TEST_MESSAGE_SIZE
#define ASSOCIATED_DATA_SIZE TEST_ASSOCIATED_DATA_SIZE
#endif

/* Scenario 1 data */
#if defined(SCENARIO) && (SCENARIO_1 == SCENARIO)
#define MESSAGE_SIZE 102
#define ASSOCIATED_DATA_SIZE 0
#endif

/* Scenario 2 data */
#if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)
#define MESSAGE_SIZE 0
#define ASSOCIATED_DATA_SIZE 111
#endif

/* Scenario 3 data */
#if defined(SCENARIO) && (SCENARIO_3 == SCENARIO)
#define MESSAGE_SIZE 86
#define ASSOCIATED_DATA_SIZE 25
#endif

/* Scenario 4 data */
#if defined(SCENARIO) && (SCENARIO_4 == SCENARIO)
#define MESSAGE_SIZE 1264
#define ASSOCIATED_DATA_SIZE 0
#endif

/* Scenario 5 data */
#if defined(SCENARIO) && (SCENARIO_5 == SCENARIO)
#define MESSAGE_SIZE 0
#define ASSOCIATED_DATA_SIZE 1264
#endif

/* Scenario 6 data */
#if defined(SCENARIO) && (SCENARIO_6 == SCENARIO)
#define MESSAGE_SIZE 1224
#define ASSOCIATED_DATA_SIZE 40
#endif

/*
 *
 * MEASURE_CYCLE_COUNT values:
 * ... MEASURE_CYCLE_COUNT_DISABLED 0 - measure cycle count is disabled
 * ... MEASURE_CYCLE_COUNT_ENABLED 1 - measure cycle count is enabled
 *
 */
#define MEASURE_CYCLE_COUNT_DISABLED 0
#define MEASURE_CYCLE_COUNT_ENABLED 1

#ifndef MEASURE_CYCLE_COUNT
#define MEASURE_CYCLE_COUNT MEASURE_CYCLE_COUNT_DISABLED
#endif


/*
 *
 * Align memory boundaries in bytes
 *
 */
#define ALIGN_PC_BOUNDRY 64
#define ALIGN_AVR_BOUNDRY 2
#define ALIGN_MSP_BOUNDRY 2
#define ALIGN_ARM_BOUNDRY 8

#if defined(PC) && !defined(ALIGNED)    /* PC ALIGNED */
#define ALIGNED __attribute__ ((aligned(ALIGN_PC_BOUNDRY)))
#endif /* PC ALIGNED */

#if defined(AVR) && !defined(ALIGNED)   /* AVR ALIGNED */
#define ALIGNED __attribute__ ((aligned(ALIGN_AVR_BOUNDRY)))
#endif /* AVR ALIGNED */

#if defined(MSP) && !defined(ALIGNED)   /* MSP ALIGNED */
#define ALIGNED __attribute__ ((aligned(ALIGN_MSP_BOUNDRY)))
#endif /* MSP ALIGNED */

#if defined(ARM) && !defined(ALIGNED)   /* ARM ALIGNED */
#define ALIGNED __attribute__ ((aligned(ALIGN_ARM_BOUNDRY)))
#endif /* ARM ALIGNED */

// By CC
#if !defined(ALIGNED)
#define ALIGNED
#endif

/*
 *
 * RAM data types
 *
 */
#define RAM_DATA_BYTE uint8_t ALIGNED
#define RAM_DATA_WORD uint16_t ALIGNED
#define RAM_DATA_DOUBLE_WORD uint32_t ALIGNED

#define READ_RAM_DATA_BYTE(x) x
#define READ_RAM_DATA_WORD(x) x
#define READ_RAM_DATA_DOUBLE_WORD(x) x


/*
 *
 * Flash/ROM data types
 *
 */
#if defined(AVR)                /* AVR */
#define ROM_DATA_BYTE const uint8_t PROGMEM ALIGNED
#define ROM_DATA_WORD const uint16_t PROGMEM ALIGNED
#define ROM_DATA_DOUBLE_WORD const uint32_t PROGMEM ALIGNED

#define READ_ROM_DATA_BYTE(x) pgm_read_byte(&x)
#define READ_ROM_DATA_WORD(x) pgm_read_word(&x)
#define READ_ROM_DATA_DOUBLE_WORD(x) pgm_read_dword(&x)
#else /* AVR */
#define ROM_DATA_BYTE const uint8_t ALIGNED
#define ROM_DATA_WORD const uint16_t ALIGNED
#define ROM_DATA_DOUBLE_WORD const uint32_t ALIGNED

#define READ_ROM_DATA_BYTE(x) x
#define READ_ROM_DATA_WORD(x) x
#define READ_ROM_DATA_DOUBLE_WORD(x) x
#endif /* AVR */


/*
 *
 * Initialization of state and absorption of key and nonce
 * ... state - the state of the cipher
 * ... key - the cipher key
 * ... nonce - the initialization vector
 *
 */
void Initialize(uint8_t *state, const uint8_t *key, const uint8_t *nonce);

/*
 *
 * Process the associated data by absorbing it in the state
 * ... state - the state of the cipher
 * ... associatedData - the associated data
 * ... associated_data_length - the associated data length length in bytes
 *
 */
// By CC - added const qualifier to associatedData
void ProcessAssociatedData(uint8_t *state, const uint8_t *associatedData,
        uint32_t associated_data_lenght);

/*
 *
 * Encrypt the given message
 * ... state - the state of the cipher
 * ... message - the message to encrypt
 * ... message_length - the message length in bytes
 *
 */
void ProcessPlaintext(uint8_t *state, uint8_t *message, uint32_t message_length);

/*
 *
 * Decrypt the given message
 * ... state - the state of the cipher
 * ... message - the message to decrypt
 * ... message_length - the message length in bytes
 *
 */
void ProcessCiphertext(uint8_t *state, uint8_t *message,
        uint32_t message_length);

/*
 *
 * Absorb key in current cipher state and generate/verify tag
 * ... state - the state of the cipher
 * ... key - the cipher key
 *
 */
// By CC - added const qualifier to key
void Finalize(uint8_t *state, const uint8_t *key);

/*
 *
 * Generate an authentication tag. Used only during the encryption phase
 * ... state - the state of the cipher
 * ... tag - The tag to be generated
 *
 */
void TagGeneration(uint8_t *state, uint8_t *tag);

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
int TagVerification(uint8_t *state, uint8_t *tag);

#endif /* CIPHER_H */
