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


#include <string.h>


#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))    /* DEBUG */

#include <stdio.h>

#ifdef AVR                      /* AVR */
#include <avr/io.h>
#include <avr/sleep.h>

#include "avr_mcu_section.h"

#ifndef F_CPU
#define F_CPU (8000000UL)
#endif

#endif /* AVR */

#endif /* DEBUG */


#ifdef MSP                      /* MSP */
#include <msp430.h>
#endif /* MSP */


#include "cipher.h"
#include "common.h"
#include "constants.h"
#include "test_vectors.h"


#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))

const char *KEY_NAME = "Key";
const char *STATE_NAME = "State";
const char *TAG_NAME = "Tag";
const char *NONCE_NAME = "Nonce";
const char *ASSOCIATED_DATA_NAME = "Associated Data";
const char *PLAINTEXT_NAME = "Plaintext";
const char *CIPHERTEXT_NAME = "Ciphertext";

const char *POST_INTIALIZATION_STATE_NAME = "Post_Initialization_State";
const char *POST_ASSOCIATED_DATA_PROCESSING_STATE_NAME =
        "Post_Associated_Data_Processing_State";
const char *POST_PLAINTEXT_PROCESSING_STATE_NAME =
        "Post_Plaintext_Processing_State";
const char *POST_CIPHERTEXT_PROCESSING_STATE_NAME =
        "Post_Ciphertext_Processing_State";
const char *POST_FINALIZATION_STATE_NAME = "Post_Finalization_State";

void DisplayData(uint8_t *data, uint16_t length, const char *name) {
    uint16_t i;

    printf("%s:\n", name);
    for (i = 0; i < length; i++) {
        printf("%02x ", data[i]);
    }
    printf("\n");
}

void DisplayVerifyData(uint8_t *data, uint16_t length, const char *name) {
    DisplayData(data, length, name);
#if defined(SCENARIO) && (SCENARIO_0 == SCENARIO)
    VerifyData(data, name);
#endif
}

void VerifyData(uint8_t *data, const char *name) {
    uint8_t correct = 1;
    uint16_t length = 0;
    uint16_t i;

    const uint8_t *expectedData;


    if (0 == strcmp(name, PLAINTEXT_NAME)) {
        expectedData = expectedPlaintext;
        length = TEST_MESSAGE_SIZE;
    }

    if (0 == strcmp(name, CIPHERTEXT_NAME)) {
        expectedData = expectedCiphertext;
        length = TEST_MESSAGE_SIZE;
    }

    if (0 == strcmp(name, KEY_NAME)) {
        expectedData = expectedKey;
        length = KEY_SIZE;
    }

    if (0 == strcmp(name, ASSOCIATED_DATA_NAME)) {
        expectedData = expectedAssociatedData;
        length = TEST_ASSOCIATED_DATA_SIZE;
    }

    if (0 == strcmp(name, NONCE_NAME)) {
        expectedData = expectedNonce;
        length = NONCE_SIZE;
    }

    if (0 == strcmp(name, TAG_NAME)) {
        expectedData = expectedTag;
        length = TAG_SIZE;
    }

    if (0 == strcmp(name, POST_INTIALIZATION_STATE_NAME)) {
        expectedData = expectedPostInitializationState;
        length = STATE_SIZE;
    }

    if (0 == strcmp(name, POST_ASSOCIATED_DATA_PROCESSING_STATE_NAME)) {
        expectedData = expectedPostAssociatedDataProcessingState;
        length = STATE_SIZE;
    }

    if (0 == strcmp(name, POST_PLAINTEXT_PROCESSING_STATE_NAME)) {
        expectedData = expectedPostPlaintextProcessingState;
        length = STATE_SIZE;
    }

    if (0 == strcmp(name, POST_CIPHERTEXT_PROCESSING_STATE_NAME)) {
        expectedData = expectedPostPlaintextProcessingState;
        length = STATE_SIZE;
    }

    if (0 == strcmp(name, POST_FINALIZATION_STATE_NAME)) {
        expectedData = expectedPostFinalizationState;
        length = STATE_SIZE;
    }

    if (0 == length) {
        return;
    }


    printf("Expected %s:\n", name);
    for (i = 0; i < length; i++) {
        printf("%02x ", expectedData[i]);
        if (expectedData[i] != data[i]) {
            correct = 0;
        }
    }
    printf("\n");

    if (correct) {
        printf("CORRECT!\n");
    } else {
        printf("WRONG!\n");
    }
}

#endif


void BeginEncryptionInitialization() {
#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))
    printf("->Encryption initialization begin\n");
#endif
}

void EndEncryptionInitialization() {
#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))
    printf("->Encryption initialization end\n");
#endif
}

void BeginEncryptionAssociatedDataProcessing() {
#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))
    printf("->Encryption associated data processing begin\n");
#endif
}

void EndEncryptionAssociatedDataProcessing() {
#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))
    printf("->Encryption associated data processing end\n");
#endif
}

void BeginPlaintextProcessing() {
#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))
    printf("->Plaintext processing begin\n");
#endif
}

void EndPlaintextProcessing() {
#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))
    printf("->Plaintext processing end\n");
#endif
}

void BeginEncryptionFinalization() {
#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))
    printf("->Encryption finalization begin\n");
#endif
}

void EndEncryptionFinalization() {
#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))
    printf("->Encryption finalization end\n");
#endif
}

void BeginTagGeneration() {
#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))
    printf("->Tag generation begin\n");
#endif
}

void EndTagGeneration() {
#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))
    printf("->Tag generation end\n");
#endif
}

void BeginDecryptionInitialization() {
#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))
    printf("->Decryption initialization begin\n");
#endif
}

void EndDecryptionInitialization() {
#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))
    printf("->Decryption initialization end\n");
#endif
}

void BeginDecryptionAssociatedDataProcessing() {
#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))
    printf("->Decryption associated data processing begin\n");
#endif
}

void EndDecryptionAssociatedDataProcessing() {
#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))
    printf("->Decryption associated data processing end\n");
#endif
}

void BeginCiphertextProcessing() {
#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))
    printf("->Ciphertext processing begin\n");
#endif
}

void EndCiphertextProcessing() {
#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))
    printf("->Ciphertext processing end\n");
#endif
}

void BeginDecryptionFinalization() {
#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))
    printf("->Decryption finalization begin\n");
#endif
}

void EndDecryptionFinalization() {
#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))
    printf("->Decryption finalization end\n");
#endif
}

void BeginTagVerification() {
#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))
    printf("->Tag verification begin\n");
#endif
}

void EndTagVerification() {
#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))
    printf("->Tag verification end\n");
#endif
}

#ifdef PC                       /* PC */

void InitializeDevice() {

}

void StopDevice() {

}

#endif /* PC */


#ifdef AVR                      /* AVR */

#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))    /* DEBUG */

AVR_MCU(F_CPU, "atmega128");

static int uart_putchar(char c, FILE * stream) {
    if ('\n' == c) {
        uart_putchar('\r', stream);
    }

    loop_until_bit_is_set(UCSR0A, UDRE0);
    UDR0 = c;

    return 0;
}

static FILE mystdout = FDEV_SETUP_STREAM(uart_putchar, NULL, _FDEV_SETUP_WRITE);
AVR_MCU_SIMAVR_CONSOLE(&UDR0);

#endif /* DEBUG */

void InitializeDevice() {
#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))
    stdout = &mystdout;
#endif
}

void StopDevice() {
#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))
    sleep_cpu();
#endif
}

#endif /* AVR */


#ifdef MSP                      /* MSP */

void InitializeDevice() {

}

void StopDevice() {

}

#endif /* MSP */


#ifdef ARM                      /* ARM */

/*
 *
 * init() is defined in the sam3x8e library, so we only need a declaration here
 *
 */
extern void init(void);

void InitializeDevice() {
    init();
}

void StopDevice() {

}

#endif /* ARM */


void InitializeKey(uint8_t *key) {
    uint16_t i;

    for (i = 0; i < KEY_SIZE; i++) {
        key[i] = expectedKey[i];
    }
}


void InitializeNonce(uint8_t *nonce) {
    uint16_t i;

    for (i = 0; i < NONCE_SIZE; i++) {
        nonce[i] = expectedNonce[i];
    }
}


void InitializePlaintext(uint8_t *plaintextBlock) {
    uint16_t i;

    for (i = 0; i < TEST_MESSAGE_SIZE; i++) {
        plaintextBlock[i] = expectedPlaintext[i];
    }
}


void InitializeCiphertextBlock(uint8_t *ciphertextBlock) {
    uint16_t i;

    for (i = 0; i < TEST_MESSAGE_SIZE; i++) {
        ciphertextBlock[i] = expectedCiphertext[i];
    }
}


void InitializeAssociatedDataBlock(uint8_t *associatedDataBlock) {
    uint16_t i;

    for (i = 0; i < TEST_ASSOCIATED_DATA_SIZE; i++) {
        associatedDataBlock[i] = expectedAssociatedData[i];
    }
}


void InitializeTag(uint8_t *tag) {
    uint16_t i;

    for (i = 0; i < TAG_SIZE; i++) {
        tag[i] = expectedTag[i];
    }
}


void InitializeMessage(uint8_t *message, int length) {
    uint16_t i;

    for (i = 0; i < length; i++) {
        message[i] = length - i;
    }
}


void InitializeAssociatedData(uint8_t *associatedData, int length) {
    uint16_t i;

    for (i = 0; i < length; i++) {
        associatedData[i] = length - i;
    }
}
