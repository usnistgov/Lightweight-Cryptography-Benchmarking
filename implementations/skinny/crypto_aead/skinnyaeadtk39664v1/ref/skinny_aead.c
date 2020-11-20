/*
 * SKINNY-AEAD Reference C Implementation
 *
 * Copyright 2018:
 *     Jeremy Jean for the SKINNY Team
 *     https://sites.google.com/site/skinnycipher/
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "skinny_aead.h"
#include "skinny_reference.h" /* Defines the SKINNY TBC family */

/*
** This file implements all the SKINNY-AEAD members.
**
** Specify in the constant SKINNY_AEAD_MEMBER the member of the family:
**
** TK3 members:
**      1: SKINNY-128-384 with 128-bit key, 128-bit nonce, 128-bit tag (PRIMARY)
**      2: SKINNY-128-384 with 128-bit key,  96-bit nonce, 128-bit tag
**      3: SKINNY-128-384 with 128-bit key, 128-bit nonce,  64-bit tag
**      4: SKINNY-128-384 with 128-bit key,  96-bit nonce,  64-bit tag
** TK2 members:
**      5: SKINNY-128-256 with 128-bit key,  96-bit nonce,  96-bit tag
**      6: SKINNY-128-256 with 128-bit key,  96-bit nonce,  64-bit tag
*/
#define SKINNY_AEAD_MEMBER 4

/*******************************************************************************
** Constant definitions
*******************************************************************************/

/*
** The following constants are used in the mode
*/

/* Control byte: Bit 4 concerns the nonce size: either 128 or 96 bits   */
#define CST_NONCE_128  (0<<4) /* 128 bits                               */
#define CST_NONCE_96   (1<<4) /*  96 bits                               */

/* Control byte: Bit 3 concerns the tag size: either 128 or 64 bits     */
#define CST_TAG_128    (0<<3) /* 128 bits                               */
#define CST_TAG_64     (1<<3) /*  64 bits                               */

/* Control byte: Bits 2-0 concerns the domain separation                */
#define CST_ENC_FULL     0x0 /* Encryption - Full block                 */
#define CST_ENC_PARTIAL  0x1 /* Encryption - Partial block              */
#define CST_AD_FULL      0x2 /* Associated Data - Full block            */
#define CST_AD_PARTIAL   0x3 /* Associated Data - Partial block         */
#define CST_TAG_FULL     0x4 /* Tag generation - Full message blocks    */
#define CST_TAG_PARTIAL  0x5 /* Tag generation - Partial message blocks */

/*
** Defines the state of the tweakey state for the SKINNY-AEAD instances.
*/
#if SKINNY_AEAD_MEMBER == 1
    #define TWEAKEY_STATE_SIZE 384 /* TK3 */
    #define TAG_SIZE           128 /* 128-bit authentication tag */

#elif SKINNY_AEAD_MEMBER == 2
    #define TWEAKEY_STATE_SIZE 384 /* TK3 */
    #define TAG_SIZE           128 /* 128-bit authentication tag */

#elif SKINNY_AEAD_MEMBER == 3
    #define TWEAKEY_STATE_SIZE 384 /* TK3 */
    #define TAG_SIZE            64 /* 64-bit authentication tag  */

#elif SKINNY_AEAD_MEMBER == 4
    #define TWEAKEY_STATE_SIZE 384 /* TK3 */
    #define TAG_SIZE            64 /* 64-bit authentication tag  */

#elif SKINNY_AEAD_MEMBER == 5
    #define TWEAKEY_STATE_SIZE 256 /* TK2 */
    #define TAG_SIZE           128 /* 128-bit authentication tag */

#elif SKINNY_AEAD_MEMBER == 6
    #define TWEAKEY_STATE_SIZE 256 /* TK2 */
    #define TAG_SIZE            64 /* 64-bit authentication tag  */

#else
    #error "Not implemented."
#endif

/*******************************************************************************
** Cipher-dependent functions
*******************************************************************************/

/*
** Modify the key part in the tweakey state
*/
static void set_key_in_tweakey(uint8_t *tweakey, const uint8_t *key) {

    if(SKINNY_AEAD_MEMBER == 1)      memcpy(tweakey+32, key, 16); /* 128-bit key */
    else if(SKINNY_AEAD_MEMBER == 2) memcpy(tweakey+32, key, 16); /* 128-bit key */
    else if(SKINNY_AEAD_MEMBER == 3) memcpy(tweakey+32, key, 16); /* 128-bit key */
    else if(SKINNY_AEAD_MEMBER == 4) memcpy(tweakey+32, key, 16); /* 128-bit key */
    else if(SKINNY_AEAD_MEMBER == 5) memcpy(tweakey+16, key, 16); /* 128-bit key */
    else if(SKINNY_AEAD_MEMBER == 6) memcpy(tweakey+16, key, 16); /* 128-bit key */

}

/*
** Modify the nonce part in the tweakey state
*/
static void set_nonce_in_tweakey(uint8_t *tweakey, const uint8_t *nonce) {

    if(SKINNY_AEAD_MEMBER == 1)      memcpy(tweakey+16, nonce, 16); /* 128-bit nonces */
    else if(SKINNY_AEAD_MEMBER == 2) memcpy(tweakey+16, nonce, 12); /*  96-bit nonces */
    else if(SKINNY_AEAD_MEMBER == 3) memcpy(tweakey+16, nonce, 16); /* 128-bit nonces */
    else if(SKINNY_AEAD_MEMBER == 4) memcpy(tweakey+16, nonce, 12); /*  96-bit nonces */
    else if(SKINNY_AEAD_MEMBER == 5) memcpy(tweakey+4,  nonce, 12); /*  96-bit nonces */
    else if(SKINNY_AEAD_MEMBER == 6) memcpy(tweakey+4,  nonce, 12); /*  96-bit nonces */

}

/*
** Modify the stage value in the tweakey state
*/
static void set_stage_in_tweakey(uint8_t *tweakey, const uint8_t value) {

    if(SKINNY_AEAD_MEMBER == 1)      tweakey[15] = CST_NONCE_128 | CST_TAG_128 | value;
    else if(SKINNY_AEAD_MEMBER == 2) tweakey[15] = CST_NONCE_96  | CST_TAG_128 | value;
    else if(SKINNY_AEAD_MEMBER == 3) tweakey[15] = CST_NONCE_128 | CST_TAG_64  | value;
    else if(SKINNY_AEAD_MEMBER == 4) tweakey[15] = CST_NONCE_96  | CST_TAG_64  | value;
    else if(SKINNY_AEAD_MEMBER == 5) tweakey[3]  = CST_NONCE_96  | CST_TAG_128 | value;
    else if(SKINNY_AEAD_MEMBER == 6) tweakey[3]  = CST_NONCE_96  | CST_TAG_64  | value;

}

/*
** LFSR used as block counter
*/
static uint64_t lfsr(const uint64_t counter) {
    
    /* x^64 + x^4 + x^3 + x + 1 */
    if(SKINNY_AEAD_MEMBER == 1)      return (counter<<1) ^ (((counter>>63)&1)?0x1b:0);
    else if(SKINNY_AEAD_MEMBER == 2) return (counter<<1) ^ (((counter>>63)&1)?0x1b:0);
    else if(SKINNY_AEAD_MEMBER == 3) return (counter<<1) ^ (((counter>>63)&1)?0x1b:0);
    else if(SKINNY_AEAD_MEMBER == 4) return (counter<<1) ^ (((counter>>63)&1)?0x1b:0);

    /* x^24 + x^4 + x^3 + x + 1 */
    else if(SKINNY_AEAD_MEMBER == 5) return (counter<<1) ^ (((counter>>23)&1)?0x1b:0);
    else if(SKINNY_AEAD_MEMBER == 6) return (counter<<1) ^ (((counter>>23)&1)?0x1b:0);

}

/*
** Modify the block number in the tweakey state
*/
static void set_block_number_in_tweakey(uint8_t *tweakey, const uint64_t block_no) {

    if(SKINNY_AEAD_MEMBER == 1) {
        for (int i=0; i<8/*15*/; ++i) {
            tweakey[0+i] = (block_no >> (8*i)) & 0xff;
        }/*i*/

    } else if(SKINNY_AEAD_MEMBER == 2) {
        for (int i=0; i<8/*15*/; ++i) {
            tweakey[0+i] = (block_no >> (8*i)) & 0xff;
        }/*i*/

    } else if(SKINNY_AEAD_MEMBER == 3) {
        for (int i=0; i<8/*15*/; ++i) {
            tweakey[0+i] = (block_no >> (8*i)) & 0xff;
        }/*i*/

    } else if(SKINNY_AEAD_MEMBER == 4) {
        for (int i=0; i<8/*15*/; ++i) {
            tweakey[0+i] = (block_no >> (8*i)) & 0xff;
        }/*i*/

    } else if(SKINNY_AEAD_MEMBER == 5) {
        tweakey[0] = (block_no >> (8*0)) & 0xff;
        tweakey[1] = (block_no >> (8*1)) & 0xff;
        tweakey[2] = (block_no >> (8*2)) & 0xff;

    } else if(SKINNY_AEAD_MEMBER == 6) {
        tweakey[0] = (block_no >> (8*0)) & 0xff;
        tweakey[1] = (block_no >> (8*1)) & 0xff;
        tweakey[2] = (block_no >> (8*2)) & 0xff;

    }

}

/*
** Encryption call to the TBC primitive used in the mode
*/
static void skinny_enc(const uint8_t* input, const uint8_t* tweakey, uint8_t* output) {

    if(SKINNY_AEAD_MEMBER == 1)      enc(input, tweakey, output, 5); /* SKINNY-128-384 (56 rounds) */
    else if(SKINNY_AEAD_MEMBER == 2) enc(input, tweakey, output, 5); /* SKINNY-128-384 (56 rounds) */
    else if(SKINNY_AEAD_MEMBER == 3) enc(input, tweakey, output, 5); /* SKINNY-128-384 (56 rounds) */
    else if(SKINNY_AEAD_MEMBER == 4) enc(input, tweakey, output, 5); /* SKINNY-128-384 (56 rounds) */
    else if(SKINNY_AEAD_MEMBER == 5) enc(input, tweakey, output, 4); /* SKINNY-128-256 (48 rounds) */
    else if(SKINNY_AEAD_MEMBER == 6) enc(input, tweakey, output, 4); /* SKINNY-128-256 (48 rounds) */

}

/*
** Decryption call to the TBC primitive used in the mode
*/
static void skinny_dec(const uint8_t* input, const uint8_t* tweakey, uint8_t* output) {

    if(SKINNY_AEAD_MEMBER == 1)      dec(input, tweakey, output, 5); /* SKINNY-128-384 (56 rounds) */
    else if(SKINNY_AEAD_MEMBER == 2) dec(input, tweakey, output, 5); /* SKINNY-128-384 (56 rounds) */
    else if(SKINNY_AEAD_MEMBER == 3) dec(input, tweakey, output, 5); /* SKINNY-128-384 (56 rounds) */
    else if(SKINNY_AEAD_MEMBER == 4) dec(input, tweakey, output, 5); /* SKINNY-128-384 (56 rounds) */
    else if(SKINNY_AEAD_MEMBER == 5) dec(input, tweakey, output, 4); /* SKINNY-128-256 (48 rounds) */
    else if(SKINNY_AEAD_MEMBER == 6) dec(input, tweakey, output, 4); /* SKINNY-128-256 (48 rounds) */

}

/*******************************************************************************
** Helper functions
*******************************************************************************/

/*
** Constant-time memcmp function
*/
static int memcmp_const(const uint8_t *a, const uint8_t *b, const size_t size)  {

    uint8_t result = 0;

    for (size_t i = 0; i < size; i++) {
        result |= a[i] ^ b[i];
    }/*i*/

    /* returns 0 if equal, nonzero otherwise */
    return result;
}

/*
** XOR an input block to another input block
*/
static void xor_values(uint8_t *v1, const uint8_t *v2) {
    int i;
    for (i=0; i<16; i++) v1[i] ^= v2[i];
}

/*******************************************************************************
** SKINNY-AEAD generic encryption and decryption functions
*******************************************************************************/

/*
** SKINNY-AEAD encryption function
*/
void skinny_aead_encrypt(const uint8_t *ass_data, size_t ass_data_len,
                         const uint8_t *message, size_t m_len,
                         const uint8_t *key,
                         const uint8_t *nonce,
                         uint8_t *ciphertext, size_t *c_len)
{

    uint64_t i;
    uint64_t j;
    uint64_t counter;
    uint8_t tweakey[TWEAKEY_STATE_SIZE/8];
    uint8_t Auth[16];
    uint8_t last_block[16];
    uint8_t Checksum[16];
    uint8_t Final[16];
    uint8_t zero_block[16];
    uint8_t Pad[16];
    uint8_t temp[16];

    /* Fill the tweakey state with zeros */
    memset(tweakey, 0, sizeof(tweakey));

    /* Set the key in the tweakey state */
    set_key_in_tweakey(tweakey, key);

    /* Set the nonce in the tweakey state */
    set_nonce_in_tweakey(tweakey, nonce);

    /* Associated data */
    memset(Auth, 0, 16);

    /* If there is associated data */
    if(ass_data_len) {

        /* Specify in the tweakey that we are processing full AD blocks */
        set_stage_in_tweakey(tweakey, CST_AD_FULL);

        /* For each full input blocks */
        i = 0;
        counter = 1;
        while (16*(i+1) <= ass_data_len) {

            /* Encrypt the current block */
            set_block_number_in_tweakey(tweakey, counter);
            skinny_enc(ass_data+16*i, tweakey, temp);

            /* Update Auth value */
            xor_values(Auth, temp);

            /* Go on with the next block */
            i++;
            counter = lfsr(counter);
        }

        /* Last block if incomplete */
        if ( ass_data_len > 16*i ) {

            /* Prepare the last padded block */
            memset(last_block, 0, 16);
            memcpy(last_block, ass_data+16*i, ass_data_len-16*i);
            last_block[ass_data_len-16*i] = 0x80;

            /* Encrypt the last block */
            set_stage_in_tweakey(tweakey, CST_AD_PARTIAL);
            set_block_number_in_tweakey(tweakey, counter);
            skinny_enc(last_block, tweakey, temp);

            /* Update the Auth value */
            xor_values(Auth, temp);
        }

    }/* if ass_data_len>0 */

    /*
    ** Now process the plaintext
    */

    /* Clear the checksum */
    memset(Checksum, 0, 16);

    /* Specify that we are now handling the plaintext */
    set_stage_in_tweakey(tweakey, CST_ENC_FULL);

    i = 0;
    counter = 1;
    while (16*(i+1) <= m_len) {

        /* Update the checksum with the current plaintext block */
        xor_values(Checksum, message+16*i);

        /* Update the tweakey state with the current block number */
        set_block_number_in_tweakey(tweakey, counter);

        /* Encrypt the current block and produce the ciphertext block */
        skinny_enc(message+16*i, tweakey, ciphertext+16*i);

        /* Update the counter */
        i++;
        counter = lfsr(counter);
    }

   /* Process incomplete block */
   if (m_len > 16*i) {

        /* Prepare the last padded block */
        memset(last_block, 0, 16);
        memcpy(last_block, message+16*i, m_len-16*i);
        last_block[m_len-16*i] = 0x80;

        /* Update the checksum */
        xor_values(Checksum, last_block);

        /* Create the zero block for encryption */
        memset(zero_block, 0, 16);

        /* Encrypt it */
        set_stage_in_tweakey(tweakey, CST_ENC_PARTIAL);
        set_block_number_in_tweakey(tweakey, counter);
        skinny_enc(zero_block, tweakey, Pad);

        /* Produce the partial ciphertext block */
        for (j=0; j<m_len-16*i; ++j) {
            ciphertext[16*i+j] = last_block[j] ^ Pad[j];
        }

        /* Encrypt the checksum */
        set_stage_in_tweakey(tweakey, CST_TAG_PARTIAL);
        counter = lfsr(counter);
        set_block_number_in_tweakey(tweakey, counter);
        skinny_enc(Checksum, tweakey, Final);

    } else {

        /* Encrypt the checksum */
        set_stage_in_tweakey(tweakey, CST_TAG_FULL);
        set_block_number_in_tweakey(tweakey, counter);
        skinny_enc(Checksum, tweakey, Final);

    }

    /* Append the authentication tag to the ciphertext */
    for (i=0; i<TAG_SIZE/8; i++) {
        ciphertext[m_len+i] = Final[i] ^ Auth[i];
    }

    /* The authentication tag is appended to the ciphertext */
    *c_len = m_len + TAG_SIZE/8;

}

/*
** SKINNY-AEAD decryption function
*/
int skinny_aead_decrypt(const uint8_t *ass_data, size_t ass_data_len,
                       uint8_t *message, size_t *m_len,
                       const uint8_t *key,
                       const uint8_t *nonce,
                       const uint8_t *ciphertext, size_t c_len)
{

    uint64_t i;
    uint64_t j;
    uint64_t counter;
    uint8_t tweakey[TWEAKEY_STATE_SIZE/8];
    uint8_t Auth[16];
    uint8_t last_block[16];
    uint8_t Checksum[16];
    uint8_t Final[16];
    uint8_t zero_block[16];
    uint8_t Pad[16];
    uint8_t Tag[16];
    uint8_t temp[16];

    /* Get the tag from the last bytes of the ciphertext */
    memset(Tag, 0, 16);
    memcpy(Tag, ciphertext+c_len-TAG_SIZE/8, TAG_SIZE/8);

    /* Update c_len to the actual size of the ciphertext (i.e., without the tag) */
    c_len -= TAG_SIZE/8;

    /* Fill the tweakey state with zeros */
    memset(tweakey, 0, sizeof(tweakey));

    /* Set the key in the tweakey state */
    set_key_in_tweakey(tweakey, key);

    /* Set the nonce in the tweakey state */
    set_nonce_in_tweakey(tweakey, nonce);

    /* Associated data */
    memset(Auth, 0, 16);

    /* If there is associated data */
    if(ass_data_len) {

        /* Specify in the tweakey that we are processing full AD blocks */
        set_stage_in_tweakey(tweakey, CST_AD_FULL);

        /* For each full input blocks */
        i = 0;
        counter = 1;
        while (16*(i+1) <= ass_data_len) {

            /* Encrypt the current block */
            set_block_number_in_tweakey(tweakey, counter);
            skinny_enc(ass_data+16*i, tweakey, temp);

            /* Update Auth value */
            xor_values(Auth, temp);

            /* Go on with the next block */
            i++;
            counter = lfsr(counter);
        }

        /* Last block if incomplete */
        if ( ass_data_len > 16*i ) {

            /* Prepare the last padded block */
            memset(last_block, 0, 16);
            memcpy(last_block, ass_data+16*i, ass_data_len-16*i);
            last_block[ass_data_len-16*i] = 0x80;

            /* Encrypt the last block */
            set_stage_in_tweakey(tweakey, CST_AD_PARTIAL);
            set_block_number_in_tweakey(tweakey, counter);
            skinny_enc(last_block, tweakey, temp);

            /* Update the Auth value */
            xor_values(Auth, temp);
        }

    }/* if ass_data_len>0 */

    /*
    ** Now process the ciphertext
    */

    /* Clear the checksum */
    memset(Checksum, 0, 16);

    /* Specify that we are now handling the plaintext */
    set_stage_in_tweakey(tweakey, CST_ENC_FULL);

    i = 0;
    counter = 1;
    while (16*(i+1) <= c_len) {

        /* Update the tweakey state with the current block number */
        set_block_number_in_tweakey(tweakey, counter);

        /* Decrypt the current block and produce the plaintext block */
        skinny_dec(ciphertext+16*i, tweakey, message+16*i);

        /* Update the checksum with the current plaintext block */
        xor_values(Checksum, message+16*i);

        /* Update the counter */
        i++;
        counter = lfsr(counter);
    }

    /* Process last block */

    /* If the block is full, simply encrypts the checksum to get the candidate tag */
    if (c_len == 16*i) {

        /* Decrypt the checksum */
        set_stage_in_tweakey(tweakey, CST_TAG_FULL);
        set_block_number_in_tweakey(tweakey, counter);
        skinny_enc(Checksum, tweakey, Final);

        /* Derive the candidate authentication tag */
        xor_values(Final, Auth);

        /* If the tags does not match, return error -1 */
        if( 0 != memcmp_const(Final, Tag, TAG_SIZE/8) ) {
            memset(message, 0, c_len);
            return -1;
        }

    } else { /* If the last block is a partial block */

        /* Prepare the full-zero block */
        memset(zero_block, 0, 16);

        /* Encrypt the zero block */
        set_stage_in_tweakey(tweakey, CST_ENC_PARTIAL);
        set_block_number_in_tweakey(tweakey, counter);
        skinny_enc(zero_block, tweakey, Pad);

        /* XOR the partial ciphertext */
        memset(last_block, 0, 16);
        memcpy(last_block, ciphertext+16*i, c_len-16*i);

        /* Partial XOR to get the plaintext block */
        for (j=0; j<c_len-16*i; ++j) {
            last_block[j] ^= Pad[j];
            message[16*i+j] = last_block[j];
        }

        /* Update the checksum */
        last_block[c_len-16*i] = 0x80;
        xor_values(Checksum, last_block);

        /* Compute the candidate authentication tag */
        set_stage_in_tweakey(tweakey, CST_TAG_PARTIAL);
        counter = lfsr(counter);
        set_block_number_in_tweakey(tweakey, counter);
        skinny_enc(Checksum, tweakey, Final);

        xor_values(Final, Auth);

        /* If the tags does not match, return error -1 */
        if( 0 != memcmp_const(Final, Tag, TAG_SIZE/8) ) {
            memset(message, 0, c_len);
            return -1;
        }
    }

    /* Returns the plaintext */
    *m_len = c_len;
    return 0;
}
