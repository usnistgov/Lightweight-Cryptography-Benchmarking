/**
 * \file cipher.h
 *
 * \brief This file contains an abstraction interface for use with the cipher
 * primitives provided by the library. It provides a common interface to all of
 * the available cipher operations.
 *
 * \author Adriaan de Jong <dejong@fox-it.com>
 */
/*
 *  Copyright (C) 2006-2018, Arm Limited (or its affiliates), All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of Mbed TLS (https://tls.mbed.org)
 */

#ifndef MBEDTLS_CIPHER_H
#define MBEDTLS_CIPHER_H

#include "platform_util.h"

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Type of operation. */
typedef enum {
    MBEDTLS_OPERATION_NONE = -1,
    MBEDTLS_DECRYPT = 0,
    MBEDTLS_ENCRYPT,
} nbedtls_operation_t;

/** Maximum length of any IV, in Bytes. */
#define MBEDTLS_MAX_IV_LENGTH      16
/** Maximum block size of any cipher, in Bytes. */
#define MBEDTLS_MAX_BLOCK_LENGTH   16

/**
 * Generic cipher context.
 */
typedef struct nbedtls_cipher_context_t
{
    /** Key length to use. */
    int key_bitlen;

    /** Operation that the key of the context has been
     * initialized for.
     */
    nbedtls_operation_t operation;

    /** The cipher-specific context. */
    void *cipher_ctx;

} nbedtls_cipher_context_t;

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_CIPHER_H */
