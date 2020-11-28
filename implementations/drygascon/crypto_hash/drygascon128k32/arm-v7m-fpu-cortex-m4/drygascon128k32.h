/*
 * Copyright (C) 2020 Southern Storm Software, Pty Ltd.
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

#ifndef LWCRYPTO_DRYGASCON_H
#define LWCRYPTO_DRYGASCON_H

/**
 * \file drygascon.h
 * \brief DryGASCON authenticated encryption algorithm.
 *
 * DryGASCON is a family of authenticated encryption algorithms based
 * around a generalised version of the ASCON permutation.  DryGASCON
 * is designed to provide some protection against power analysis and
 * fault attacks.
 *
 * There are four algorithms in the DryGASCON family:
 *
 * \li DryGASCON128k32 is an authenticated encryption algorithm with a
 * 256-bit key, a 128-bit nonce, and a 128-bit authentication tag.
 * \li DryGASCON128-HASH is a hash algorithm with a 256-bit output.
 *
 * DryGASCON128k32 and DryGASCON128-HASH are the primary members of the family.
 *
 * References: https://github.com/sebastien-riou/DryGASCON
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Size of the key for DryGASCON128.
 */
#define DRYGASCON128_KEY_SIZE 32

/**
 * \brief Size of the authentication tag for DryGASCON128.
 */
#define DRYGASCON128_TAG_SIZE 16

/**
 * \brief Size of the nonce for DryGASCON128.
 */
#define DRYGASCON128_NONCE_SIZE 16

/**
 * \brief Size of the hash output for DryGASCON128-HASH.
 */
#define DRYGASCON128_HASH_SIZE 32

/**
 * \brief Encrypts and authenticates a packet with DryGASCON128 with 32 bytes key.
 *
 * \param c Buffer to receive the output.
 * \param clen On exit, set to the length of the output which includes
 * the ciphertext and the 16 byte authentication tag.
 * \param m Buffer that contains the plaintext message to encrypt.
 * \param mlen Length of the plaintext message in bytes.
 * \param ad Buffer that contains associated data to authenticate
 * along with the packet but which does not need to be encrypted.
 * \param adlen Length of the associated data in bytes.
 * \param nsec Secret nonce - not used by this algorithm.
 * \param npub Points to the public nonce for the packet which must
 * be 16 bytes in length.
 * \param k Points to the 32 bytes of the key to use to encrypt the packet.
 *
 * \return 0 on success, or non null value if there was an error in
 * the parameters.
 *
 * \sa drygascon128k32_aead_decrypt()
 */
int drygascon128k32_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Decrypts and authenticates a packet with DryGASCON128 with 32 bytes key.
 *
 * \param m Buffer to receive the plaintext message on output.
 * \param mlen Receives the length of the plaintext message on output.
 * \param nsec Secret nonce - not used by this algorithm.
 * \param c Buffer that contains the ciphertext and authentication
 * tag to decrypt.
 * \param clen Length of the input data in bytes, which includes the
 * ciphertext and the 16 byte authentication tag.
 * \param ad Buffer that contains associated data to authenticate
 * along with the packet but which does not need to be encrypted.
 * \param adlen Length of the associated data in bytes.
 * \param npub Points to the public nonce for the packet which must
 * be 16 bytes in length.
 * \param k Points to the 32 bytes of the key to use to decrypt the packet.
 *
 * \return 0 on success, non null if the authentication tag was incorrect,
 * or if there was an error in the parameters.
 *
 * \sa drygascon128k32_aead_encrypt()
 */
int drygascon128k32_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Hashes a block of input data with DRYGASCON128.
 *
 * \param out Buffer to receive the hash output which must be at least
 * DRYGASCON128_HASH_SIZE bytes in length.
 * \param in Points to the input data to be hashed.
 * \param inlen Length of the input data in bytes.
 *
 * \return Returns zero on success or non null if there was an error in the
 * parameters.
 */
int drygascon128_hash
    (unsigned char *out, const unsigned char *in, unsigned long long inlen);

#ifdef __cplusplus
}
#endif

#endif
