/*
 * Copyright (C) 2021 Southern Storm Software, Pty Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#ifndef LWCRYPTO_XOODYAK_AEAD_H
#define LWCRYPTO_XOODYAK_AEAD_H

#include <stddef.h>

/**
 * \file xoodyak-aead.h
 * \brief Xoodyak authenticated encryption algorithm.
 *
 * Xoodyak is an authenticated encryption and hash algorithm pair based
 * around the 384-bit Xoodoo permutation that is similar in structure to
 * Keccak but is more efficient than Keccak on 32-bit embedded devices.
 * The Cyclist mode of operation is used to convert the permutation
 * into a sponge for the higher-level algorithms.
 *
 * The Xoodyak encryption mode has a 128-bit key, a 128-bit nonce,
 * and a 128-bit authentication tag.
 *
 * The Xoodyak specification describes a re-keying mechanism where the
 * key for one packet is used to derive the key to use on the next packet.
 * This provides some resistance against side channel attacks by making
 * the session key a moving target.  This library does not currently
 * implement re-keying.
 *
 * References: https://keccak.team/xoodyak.html
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Size of the key for Xoodyak.
 */
#define XOODYAK_KEY_SIZE 16

/**
 * \brief Size of the authentication tag for Xoodyak.
 */
#define XOODYAK_TAG_SIZE 16

/**
 * \brief Size of the nonce for Xoodyak.
 */
#define XOODYAK_NONCE_SIZE 16

/**
 * \brief Encrypts and authenticates a packet with Xoodyak.
 *
 * \param c Buffer to receive the output.
 * \param clen On exit, set to the length of the output which includes
 * the ciphertext and the 16 byte authentication tag.
 * \param m Buffer that contains the plaintext message to encrypt.
 * \param mlen Length of the plaintext message in bytes.
 * \param ad Buffer that contains associated data to authenticate
 * along with the packet but which does not need to be encrypted.
 * \param adlen Length of the associated data in bytes.
 * \param npub Points to the public nonce for the packet which must
 * be 16 bytes in length.
 * \param k Points to the 16 bytes of the key to use to encrypt the packet.
 *
 * \return 0 on success, or a negative value if there was an error in
 * the parameters.
 *
 * \sa xoodyak_aead_decrypt()
 */
int xoodyak_aead_encrypt
    (unsigned char *c, size_t *clen,
     const unsigned char *m, size_t mlen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Decrypts and authenticates a packet with Xoodyak.
 *
 * \param m Buffer to receive the plaintext message on output.
 * \param mlen Receives the length of the plaintext message on output.
 * \param c Buffer that contains the ciphertext and authentication
 * tag to decrypt.
 * \param clen Length of the input data in bytes, which includes the
 * ciphertext and the 16 byte authentication tag.
 * \param ad Buffer that contains associated data to authenticate
 * along with the packet but which does not need to be encrypted.
 * \param adlen Length of the associated data in bytes.
 * \param npub Points to the public nonce for the packet which must
 * be 16 bytes in length.
 * \param k Points to the 16 bytes of the key to use to decrypt the packet.
 *
 * \return 0 on success, -1 if the authentication tag was incorrect,
 * or some other negative number if there was an error in the parameters.
 *
 * \sa xoodyak_aead_encrypt()
 */
int xoodyak_aead_decrypt
    (unsigned char *m, size_t *mlen,
     const unsigned char *c, size_t clen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k);

#ifdef __cplusplus
}
#endif

#endif
