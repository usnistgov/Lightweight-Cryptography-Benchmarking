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


#ifndef COMMON_H
#define COMMON_H


/*
 *
 * Debug levels:
 * ... DEBUG_NO 0 - do not debug
 * ... DEBUG_LOW 1 - minimum debug level
 * ... DEBUG_MEDIUM 3 - medium debug level
 * ... DEBUG_HIGHT 7 - maximum debug level
 *
 */
#define DEBUG_NO 0
#define DEBUG_LOW 1
#define DEBUG_MEDIUM 3
#define DEBUG_HIGH 7


#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))    /* DEBUG */

extern const char *KEY_NAME;
extern const char *STATE_NAME;
extern const char *TAG_NAME;
extern const char *NONCE_NAME;
extern const char *ASSOCIATED_DATA_NAME;
extern const char *PLAINTEXT_NAME;
extern const char *CIPHERTEXT_NAME;

extern const char *POST_PLAINTEXT_PROCESSING_STATE_NAME;
extern const char *POST_CIPHERTEXT_PROCESSING_STATE_NAME;
extern const char *POST_INTIALIZATION_STATE_NAME;
extern const char *POST_ASSOCIATED_DATA_PROCESSING_STATE_NAME;
extern const char *POST_FINALIZATION_STATE_NAME;

/*
 *
 * Display the given data arrray in hexadecimal
 * ... data - the data array to be displayed
 * ... length - the length in bytes of the data array
 * ... name - the name of the data array
 *
 */
void DisplayData(uint8_t *data, uint16_t length, const char *name);

/*
 *
 * Display and verify the given data arrray in hexadecimal
 * ... data - the data array to be displayed
 * ... length - the length in bytes of the data array
 * ... name - the name of the data array
 *
 */
void DisplayVerifyData(uint8_t *data, uint16_t length, const char *name);

/*
 *
 * Verify if the given data is the same with the expected data
 * ... data - the data array to check
 * ... name - the name of the data array
 *
 */
void VerifyData(uint8_t *data, const char *name);

#endif /* DEBUG */



#ifdef ARM                      /* ARM */

#if defined(MEASURE_CYCLE_COUNT) && \
    (MEASURE_CYCLE_COUNT_ENABLED == MEASURE_CYCLE_COUNT)    /* MEASURE_CYCLE_COUNT */

#define BEGIN_ENCRYPTION_INITIALIZATION() CYCLE_COUNT_START
#define END_ENCRYPTION_INITIALIZATION() \
    CYCLE_COUNT_STOP; \
    printf("EncryptionInitializationCycleCount: %u\n", CYCLE_COUNT_ELAPSED)

#define BEGIN_ENCRYPTION_ASSOCIATED_DATA_PROCESSING() CYCLE_COUNT_START
#define END_ENCRYPTION_ASSOCIATED_DATA_PROCESSING() \
    CYCLE_COUNT_STOP; \
    printf("EncryptionProcessAssociatedDataCycleCount: %u\n", CYCLE_COUNT_ELAPSED)

#define BEGIN_PLAINTEXT_PROCESSING() CYCLE_COUNT_START
#define END_PLAINTEXT_PROCESSING() \
    CYCLE_COUNT_STOP; \
    printf("ProcessPlaintextCycleCount: %u\n", CYCLE_COUNT_ELAPSED)

#define BEGIN_ENCRYPTION_FINALIZATION() CYCLE_COUNT_START
#define END_ENCRYPTION_FINALIZATION() \
    CYCLE_COUNT_STOP; \
    printf("EncryptionFinalizationCycleCount: %u\n", CYCLE_COUNT_ELAPSED)

#define BEGIN_TAG_GENERATION() CYCLE_COUNT_START
#define END_TAG_GENERATION() \
    CYCLE_COUNT_STOP; \
    printf("TagGenerationCycleCount: %u\n", CYCLE_COUNT_ELAPSED)

#define BEGIN_DECRYPTION_INITIALIZATION() CYCLE_COUNT_START
#define END_DECRYPTION_INITIALIZATION() \
    CYCLE_COUNT_STOP; \
    printf("DecryptionInitializationCycleCount: %u\n", CYCLE_COUNT_ELAPSED)

#define BEGIN_DECRYPTION_ASSOCIATED_DATA_PROCESSING() CYCLE_COUNT_START
#define END_DECRYPTION_ASSOCIATED_DATA_PROCESSING() \
    CYCLE_COUNT_STOP; \
    printf("DecryptionProcessAssociatedDataCycleCount: %u\n", CYCLE_COUNT_ELAPSED)

#define BEGIN_CIPHERTEXT_PROCESSING() CYCLE_COUNT_START
#define END_CIPHERTEXT_PROCESSING() \
    CYCLE_COUNT_STOP; \
    printf("ProcessCiphertextCycleCount: %u\n", CYCLE_COUNT_ELAPSED)

#define BEGIN_TAG_VERIFICATION() CYCLE_COUNT_START
#define END_TAG_VERIFICATION() \
    CYCLE_COUNT_STOP; \
    printf("TagVerificationCycleCount: %u\n", CYCLE_COUNT_ELAPSED)

#define BEGIN_DECRYPTION_FINALIZATION() CYCLE_COUNT_START
#define END_DECRYPTION_FINALIZATION() \
    CYCLE_COUNT_STOP; \
    printf("DecryptionFinalizationCycleCount: %u\n", CYCLE_COUNT_ELAPSED)

#define DONE() printf("Done\n")

#else /* MEASURE_CYCLE_COUNT */

#define BEGIN_ENCRYPTION_INITIALIZATION() BeginEncryptionInitialization()
#define END_ENCRYPTION_INITIALIZATION() EndEncryptionInitialization()

#define BEGIN_ENCRYPTION_ASSOCIATED_DATA_PROCESSING() BeginEncryptionAssociatedDataProcessing()
#define END_ENCRYPTION_ASSOCIATED_DATA_PROCESSING() EndEncryptionAssociatedDataProcessing()

#define BEGIN_PLAINTEXT_PROCESSING() BeginPlaintextProcessing()
#define END_PLAINTEXT_PROCESSING() EndPlaintextProcessing()

#define BEGIN_ENCRYPTION_FINALIZATION() BeginEncryptionFinalization()
#define END_ENCRYPTION_FINALIZATION() EndEncryptionFinalization()

#define BEGIN_TAG_GENERATION() BeginTagGeneration()
#define END_TAG_GENERATION() EndTagGeneration()

#define BEGIN_DECRYPTION_INITIALIZATION() BeginDecryptionInitialization()
#define END_DECRYPTION_INITIALIZATION() EndDecryptionInitialization()

#define BEGIN_DECRYPTION_ASSOCIATED_DATA_PROCESSING() BeginDecryptionAssociatedDataProcessing()
#define END_DECRYPTION_ASSOCIATED_DATA_PROCESSING() EndDecryptionAssociatedDataProcessing()

#define BEGIN_CIPHERTEXT_PROCESSING() BeginCiphertextProcessing()
#define END_CIPHERTEXT_PROCESSING() EndCiphertextProcessing()

#define BEGIN_DECRYPTION_FINALIZATION() BeginDecryptionFinalization()
#define END_DECRYPTION_FINALIZATION() EndDecryptionFinalization()

#define BEGIN_TAG_VERIFICATION() BeginTagVerification()
#define END_TAG_VERIFICATION() EndTagVerification()

#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))
#define DONE() printf("Done\n");
#else
#define DONE()
#endif

#endif /* MEASURE_CYCLE_COUNT */

#else /* ARM */

#ifdef PC                       /* PC */

#if defined(MEASURE_CYCLE_COUNT) && \
    (MEASURE_CYCLE_COUNT_ENABLED == MEASURE_CYCLE_COUNT)    /* MEASURE_CYCLE_COUNT */

#define BEGIN_ENCRYPTION_INITIALIZATION() CYCLE_COUNT_START
#define END_ENCRYPTION_INITIALIZATION() \
    CYCLE_COUNT_STOP; \
    printf("EncryptionInitializationCycleCount: %"PRIu64"\n", CYCLE_COUNT_ELAPSED)

#define BEGIN_ENCRYPTION_ASSOCIATED_DATA_PROCESSING() CYCLE_COUNT_START
#define END_ENCRYPTION_ASSOCIATED_DATA_PROCESSING() \
    CYCLE_COUNT_STOP; \
    printf("EncryptionProcessAssociatedDataCycleCount: %"PRIu64"\n", CYCLE_COUNT_ELAPSED)

#define BEGIN_PLAINTEXT_PROCESSING() CYCLE_COUNT_START
#define END_PLAINTEXT_PROCESSING() \
    CYCLE_COUNT_STOP; \
    printf("ProcessPlaintextCycleCount: %"PRIu64"\n", CYCLE_COUNT_ELAPSED)

#define BEGIN_ENCRYPTION_FINALIZATION() CYCLE_COUNT_START
#define END_ENCRYPTION_FINALIZATION() \
    CYCLE_COUNT_STOP; \
    printf("EncryptionFinalizationCycleCount: %"PRIu64"\n", CYCLE_COUNT_ELAPSED)

#define BEGIN_TAG_GENERATION() CYCLE_COUNT_START
#define END_TAG_GENERATION() \
    CYCLE_COUNT_STOP; \
    printf("TagGenerationCycleCount: %"PRIu64"\n", CYCLE_COUNT_ELAPSED)

#define BEGIN_DECRYPTION_INITIALIZATION() CYCLE_COUNT_START
#define END_DECRYPTION_INITIALIZATION() \
    CYCLE_COUNT_STOP; \
    printf("DecryptionInitializationCycleCount: %"PRIu64"\n", CYCLE_COUNT_ELAPSED)

#define BEGIN_DECRYPTION_ASSOCIATED_DATA_PROCESSING() CYCLE_COUNT_START
#define END_DECRYPTION_ASSOCIATED_DATA_PROCESSING() \
    CYCLE_COUNT_STOP; \
    printf("DecryptionProcessAssociatedDataCycleCount: %"PRIu64"\n", CYCLE_COUNT_ELAPSED)

#define BEGIN_CIPHERTEXT_PROCESSING() CYCLE_COUNT_START
#define END_CIPHERTEXT_PROCESSING() \
    CYCLE_COUNT_STOP; \
    printf("ProcessCiphertextCycleCount: %"PRIu64"\n", CYCLE_COUNT_ELAPSED)

#define BEGIN_DECRYPTION_FINALIZATION() CYCLE_COUNT_START
#define END_DECRYPTION_FINALIZATION() \
    CYCLE_COUNT_STOP; \
    printf("DecryptionFinalizationCycleCount: %"PRIu64"\n", CYCLE_COUNT_ELAPSED)

#define BEGIN_TAG_VERIFICATION() CYCLE_COUNT_START
#define END_TAG_VERIFICATION() \
    CYCLE_COUNT_STOP; \
    printf("TagVerificationCycleCount: %"PRIu64"\n", CYCLE_COUNT_ELAPSED)

#define DONE()

#else /* MEASURE_CYCLE_COUNT */

#define BEGIN_ENCRYPTION_INITIALIZATION() BeginEncryptionInitialization()
#define END_ENCRYPTION_INITIALIZATION() EndEncryptionInitialization()

#define BEGIN_ENCRYPTION_ASSOCIATED_DATA_PROCESSING() BeginEncryptionAssociatedDataProcessing()
#define END_ENCRYPTION_ASSOCIATED_DATA_PROCESSING() EndEncryptionAssociatedDataProcessing()

#define BEGIN_PLAINTEXT_PROCESSING() BeginPlaintextProcessing()
#define END_PLAINTEXT_PROCESSING() EndPlaintextProcessing()

#define BEGIN_ENCRYPTION_FINALIZATION() BeginEncryptionFinalization()
#define END_ENCRYPTION_FINALIZATION() EndEncryptionFinalization()

#define BEGIN_TAG_GENERATION() BeginTagGeneration()
#define END_TAG_GENERATION() EndTagGeneration()

#define BEGIN_DECRYPTION_INITIALIZATION() BeginDecryptionInitialization()
#define END_DECRYPTION_INITIALIZATION() EndDecryptionInitialization()

#define BEGIN_DECRYPTION_ASSOCIATED_DATA_PROCESSING() BeginDecryptionAssociatedDataProcessing()
#define END_DECRYPTION_ASSOCIATED_DATA_PROCESSING() EndDecryptionAssociatedDataProcessing()

#define BEGIN_CIPHERTEXT_PROCESSING() BeginCiphertextProcessing()
#define END_CIPHERTEXT_PROCESSING() EndCiphertextProcessing()

#define BEGIN_DECRYPTION_FINALIZATION() BeginDecryptionFinalization()
#define END_DECRYPTION_FINALIZATION() EndDecryptionFinalization()

#define BEGIN_TAG_VERIFICATION() BeginTagVerification()
#define END_TAG_VERIFICATION() EndTagVerification()

#define DONE()

#endif /* MEASURE_CYCLE_COUNT */

#else /* PC */
#define BEGIN_ENCRYPTION_INITIALIZATION() BeginEncryptionInitialization()
#define END_ENCRYPTION_INITIALIZATION() EndEncryptionInitialization()

#define BEGIN_ENCRYPTION_ASSOCIATED_DATA_PROCESSING() BeginEncryptionAssociatedDataProcessing()
#define END_ENCRYPTION_ASSOCIATED_DATA_PROCESSING() EndEncryptionAssociatedDataProcessing()

#define BEGIN_PLAINTEXT_PROCESSING() BeginPlaintextProcessing()
#define END_PLAINTEXT_PROCESSING() EndPlaintextProcessing()

#define BEGIN_ENCRYPTION_FINALIZATION() BeginEncryptionFinalization()
#define END_ENCRYPTION_FINALIZATION() EndEncryptionFinalization()

#define BEGIN_TAG_GENERATION() BeginTagGeneration()
#define END_TAG_GENERATION() EndTagGeneration()

#define BEGIN_DECRYPTION_INITIALIZATION() BeginDecryptionInitialization()
#define END_DECRYPTION_INITIALIZATION() EndDecryptionInitialization()

#define BEGIN_DECRYPTION_ASSOCIATED_DATA_PROCESSING() BeginDecryptionAssociatedDataProcessing()
#define END_DECRYPTION_ASSOCIATED_DATA_PROCESSING() EndDecryptionAssociatedDataProcessing()

#define BEGIN_CIPHERTEXT_PROCESSING() BeginCiphertextProcessing()
#define END_CIPHERTEXT_PROCESSING() EndCiphertextProcessing()

#define BEGIN_DECRYPTION_FINALIZATION() BeginDecryptionFinalization()
#define END_DECRYPTION_FINALIZATION() EndDecryptionFinalization()

#define BEGIN_TAG_VERIFICATION() BeginTagVerification()
#define END_TAG_VERIFICATION() EndTagVerification()

#define DONE()

#endif /* PC */

#endif /* ARM */



/*
 *
 * Mark the beginning of the encryption initialization
 *
 */
void BeginEncryptionInitialization();

/*
 *
 * Mark the end of the encryption initialization
 *
 */
void EndEncryptionInitialization();

/*
 *
 * Mark the beginning of the encryption associated data processing
 *
 */
void BeginEncryptionAssociatedDataProcessing();

/*
 *
 * Mark the end of the encryptionassociated data processing
 *
 */
void EndEncryptionAssociatedDataProcessing();

/*
 *
 * Mark the beginning of the encryption - plaintext processing
 *
 */
void BeginPlaintextProcessing();

/*
 *
 * Mark the end of the encryption - plaintext processing
 *
 */
void EndPlaintextProcessing();

/*
 *
 * Mark the beginning of the encryption finalization
 *
 */
void BeginEncryptionFinalization();

/*
 *
 * Mark the end of the encryption finalization
 *
 */
void EndEncryptionFinalization();

/*
 *
 * Mark the beginning of tag generation
 *
 */
void BeginTagGeneration();

/*
 *
 * Mark the end of tag generation
 *
 */
void EndTagGeneration();
/*
 *
 * Mark the beginning of the decryption initialization
 *
 */
void BeginDecryptionInitialization();

/*
 *
 * Mark the end of the decryption initialization
 *
 */
void EndDecryptionInitialization();

/*
 *
 * Mark the beginning of the decryption associated data processing
 *
 */
void BeginDecryptionAssociatedDataProcessing();

/*
 *
 * Mark the beginning of the decryption associated data processing
 *
 */
void EndDecryptionAssociatedDataProcessing();
/*
 *
 * Mark the beginning decryption - ciphertext processing
 *
 */
void BeginCiphertextProcessing();

/*
 *
 * Mark the end decryption - ciphertext processing
 *
 */
void EndCiphertextProcessing();


/*
 *
 * Mark the beginning of decryption finalization
 *
 */
void BeginDecryptionFinalization();

/*
 *
 * Mark the end of decryption finalization
 *
 */
void EndDecryptionFinalization();

/*
 *
 * Mark the beginning of tag verification
 *
 */
void BeginTagVerification();

/*
 *
 * Mark the end of tag verification
 *
 */
void EndTagVerification();

/*
 *
 * Initialize the device (architecture dependent)
 *
 */
void InitializeDevice();

/*
 *
 * Stop the device (architecture dependent)
 *
 */
void StopDevice();


/*
 *
 * Initialize the cipher key
 * ... key - the key to be initialized
 *
 */
void InitializeKey(uint8_t *key);

/*
 *
 * Initialize the nonce
 * ... iv - the nonce block to be initialized
 *
 */
void InitializeNonce(uint8_t *nonce);

/*
 *
 * Initialize the plaintext block
 * ... plaintextBlock - plaintext block to be initialized
 *
 */
void InitializePlaintext(uint8_t *plaintextBlock);

/*
 *
 * Initialize the ciphertext block;
 * ... ciphertextBlock - ciphertext block to be initialized
 *
 */
void InitializeCiphertextBlock(uint8_t *ciphertextBlock);

/*
 *
 * Initialize the associated data block;
 * ... associatedDataBlock - associated data block to be initialized
 *
 */
void InitializeAssociatedDataBlock(uint8_t *associatedDataBlock);

/*
 *
 * Initialize the tag
 * ... tag - tag created by encryption/decryption processes
 *
 */
void InitializeTag(uint8_t *tag);

/*
 *
 * Initialize the data
 * ... data - the data array to be initialized
 * ... length - the length of the data array to be initialized
 *
 */
void InitializeMessage(uint8_t *data, int length);

/*
 *
 * Initialize the counter
 * ... counter - the counter block to be initialized
 *
 */
void InitializeAssociatedData(uint8_t *associatedData, int length);

#endif /* COMMON_H */
