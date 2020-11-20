/*
 *  NIST SP800-38D compliant GCM implementation
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
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
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

/*
 * http://csrc.nist.gov/publications/nistpubs/800-38D/SP-800-38D.pdf
 *
 * See also:
 * [MGV] http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf
 *
 * We use the algorithm described as Shoup's method with 4-bit tables in
 * [MGV] 4.1, pp. 12-13, to enhance speed without using too much memory.
 */

#include "platform_util.h"

#include "gcm.h"
#include "aes.h"
#include "api.h"
#include "crypto_aead.h"

#include <string.h>

/* Parameter validation macros */
#define GCM_VALIDATE_RET( cond ) \
    MBEDTLS_INTERNAL_VALIDATE_RET( cond, MBEDTLS_ERR_GCM_BAD_INPUT )
#define GCM_VALIDATE( cond ) \
    MBEDTLS_INTERNAL_VALIDATE( cond )

/*
 * 32-bit integer manipulation macros (big endian)
 */
#ifndef GET_UINT32_BE
#define GET_UINT32_BE(n,b,i)                            \
{                                                       \
    (n) = ( (uint32_t) (b)[(i)    ] << 24 )             \
        | ( (uint32_t) (b)[(i) + 1] << 16 )             \
        | ( (uint32_t) (b)[(i) + 2] <<  8 )             \
        | ( (uint32_t) (b)[(i) + 3]       );            \
}
#endif

#ifndef PUT_UINT32_BE
#define PUT_UINT32_BE(n,b,i)                            \
{                                                       \
    (b)[(i)    ] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 3] = (unsigned char) ( (n)       );       \
}
#endif



/*
 * Initialize a context
 */
void nbedtls_gcm_init( nbedtls_gcm_context *ctx )
{
    GCM_VALIDATE( ctx != NULL );
    memset( ctx, 0, sizeof( nbedtls_gcm_context ) );
}

#define nbedtls_cipher_update(ctx, input, output) \
	nbedtls_aes_crypt_ecb((ctx)->cipher_ctx, MBEDTLS_ENCRYPT, input, output)

/*
 * Encrypt function for NIST API
*/
int crypto_aead_encrypt(
      unsigned char *c,unsigned long long *clen,
      const unsigned char *m,unsigned long long mlen,
      const unsigned char *ad,unsigned long long adlen,
      const unsigned char *nsec,
      const unsigned char *npub,
      const unsigned char *k
      )
{
  (void) nsec;
  nbedtls_gcm_context ctx;
  nbedtls_aes_context aes;
  int ret;
//   unsigned long long mask = 15;
//   unsigned long long mlenp = (mlen + mask) & (~mask);
  unsigned char tag_buf[CRYPTO_ABYTES];

//  *clen = mlenp + CRYPTO_ABYTES;
  *clen = mlen + CRYPTO_ABYTES;

  nbedtls_gcm_init( &ctx );
  ctx.cipher_ctx.cipher_ctx = &aes;
  ret = nbedtls_gcm_setkey( &ctx, k, 128);
  ret = nbedtls_gcm_crypt_and_tag( &ctx, 1, mlen, npub, 12, ad, adlen, m, c, 16, tag_buf );
  nbedtls_gcm_free( &ctx );
  nbedtls_platform_zeroize( &aes, sizeof( aes ) );

  //memcpy(c + mlenp, tag_buf, CRYPTO_ABYTES);
  memcpy(c + mlen, tag_buf, CRYPTO_ABYTES);

  return ret;
}

int crypto_aead_decrypt(
  unsigned char *m, unsigned long long *mlen,
  unsigned char *nsec,
  const unsigned char *c, unsigned long long clen,
  const unsigned char *ad, unsigned long long adlen,
  const unsigned char *npub,
  const unsigned char *k
)
{
  (void) nsec;
  nbedtls_gcm_context ctx;
  nbedtls_aes_context aes;
  int ret;
  unsigned char tag_buf[CRYPTO_ABYTES];
  
  clen -= CRYPTO_ABYTES;
  memcpy(tag_buf, c + clen, CRYPTO_ABYTES);
  *mlen = clen;

  nbedtls_gcm_init( &ctx );
  ctx.cipher_ctx.cipher_ctx = &aes;
  ret = nbedtls_gcm_setkey( &ctx, k, 128);
  ret = nbedtls_gcm_auth_decrypt( &ctx, clen, npub, 12, ad, adlen, tag_buf, 16, c, m);
  nbedtls_gcm_free( &ctx );
  nbedtls_platform_zeroize( &aes, sizeof( aes ) );
  
  return ret;

}
/*
 * Precompute small multiples of H, that is set
 *      HH[i] || HL[i] = H times i,
 * where i is seen as a field element as in [MGV], ie high-order bits
 * correspond to low powers of P. The result is stored in the same way, that
 * is the high-order bit of HH corresponds to P^0 and the low-order bit of HL
 * corresponds to P^127.
 */

static int gcm_gen_table( nbedtls_gcm_context *ctx )
{
    int ret, i, j;
    uint64_t hi, lo;
    uint64_t vl, vh;
    unsigned char h[16];

    memset( h, 0, 16 );
    if( ( ret = nbedtls_cipher_update( &ctx->cipher_ctx, h, h ) ) != 0 )
        return( ret );

    /* pack h as two 64-bits ints, big-endian */
    GET_UINT32_BE( hi, h,  0  );
    GET_UINT32_BE( lo, h,  4  );
    vh = (uint64_t) hi << 32 | lo;

    GET_UINT32_BE( hi, h,  8  );
    GET_UINT32_BE( lo, h,  12 );
    vl = (uint64_t) hi << 32 | lo;

    /* 8 = 1000 corresponds to 1 in GF(2^128) */
    ctx->HL[8] = vl;
    ctx->HH[8] = vh;

    /* 0 corresponds to 0 in GF(2^128) */
    ctx->HH[0] = 0;
    ctx->HL[0] = 0;

    for( i = 4; i > 0; i >>= 1 )
    {
        uint32_t T = ( vl & 1 ) * 0xe1000000U;
        vl  = ( vh << 63 ) | ( vl >> 1 );
        vh  = ( vh >> 1 ) ^ ( (uint64_t) T << 32);

        ctx->HL[i] = vl;
        ctx->HH[i] = vh;
    }

    for( i = 2; i <= 8; i *= 2 )
    {
        uint64_t *HiL = ctx->HL + i, *HiH = ctx->HH + i;
        vh = *HiH;
        vl = *HiL;
        for( j = 1; j < i; j++ )
        {
            HiH[j] = vh ^ ctx->HH[j];
            HiL[j] = vl ^ ctx->HL[j];
        }
    }

    return( 0 );
}

int nbedtls_gcm_setkey( nbedtls_gcm_context *ctx,
                        const unsigned char *key,
                        unsigned int keybits )
{
    int ret;

    GCM_VALIDATE_RET( ctx != NULL );
    GCM_VALIDATE_RET( key != NULL );
    GCM_VALIDATE_RET( keybits == 128 || keybits == 192 || keybits == 256 );

    ctx->cipher_ctx.key_bitlen = keybits;

    if( ( ret = nbedtls_aes_setkey_enc( ctx->cipher_ctx.cipher_ctx, key, keybits ) ) != 0)
    {
        return( ret );
    }

    if( ( ret = gcm_gen_table( ctx ) ) != 0 )
        return( ret );

    return( 0 );
}

/*
 * Shoup's method for multiplication use this table with
 *      last4[x] = x times P^128
 * where x and last4[x] are seen as elements of GF(2^128) as in [MGV]
 */
static const uint64_t last4[16] =
{
    0x0000, 0x1c20, 0x3840, 0x2460,
    0x7080, 0x6ca0, 0x48c0, 0x54e0,
    0xe100, 0xfd20, 0xd940, 0xc560,
    0x9180, 0x8da0, 0xa9c0, 0xb5e0
};

/*
 * Sets output to x times H using the precomputed tables.
 * x and output are seen as elements of GF(2^128) as in [MGV].
 */
static void gcm_mult( nbedtls_gcm_context *ctx, const unsigned char x[16],
                      unsigned char output[16] )
{
    int i = 0;
    unsigned char lo, hi, rem;
    uint64_t zh, zl;

    lo = x[15] & 0xf;

    zh = ctx->HH[lo];
    zl = ctx->HL[lo];

    for( i = 15; i >= 0; i-- )
    {
        lo = x[i] & 0xf;
        hi = x[i] >> 4;

        if( i != 15 )
        {
            rem = (unsigned char) zl & 0xf;
            zl = ( zh << 60 ) | ( zl >> 4 );
            zh = ( zh >> 4 );
            zh ^= (uint64_t) last4[rem] << 48;
            zh ^= ctx->HH[lo];
            zl ^= ctx->HL[lo];

        }

        rem = (unsigned char) zl & 0xf;
        zl = ( zh << 60 ) | ( zl >> 4 );
        zh = ( zh >> 4 );
        zh ^= (uint64_t) last4[rem] << 48;
        zh ^= ctx->HH[hi];
        zl ^= ctx->HL[hi];
    }

    PUT_UINT32_BE( zh >> 32, output, 0 );
    PUT_UINT32_BE( zh, output, 4 );
    PUT_UINT32_BE( zl >> 32, output, 8 );
    PUT_UINT32_BE( zl, output, 12 );
}

int nbedtls_gcm_starts( nbedtls_gcm_context *ctx,
                int mode,
                const unsigned char *iv,
                size_t iv_len,
                const unsigned char *add,
                size_t add_len )
{
    int ret;
    unsigned char work_buf[16];
    size_t i;
    const unsigned char *p;
    size_t use_len;

    GCM_VALIDATE_RET( ctx != NULL );
    GCM_VALIDATE_RET( iv != NULL );
    GCM_VALIDATE_RET( add_len == 0 || add != NULL );

    /* IV and AD are limited to 2^64 bits, so 2^61 bytes */
    /* IV is not allowed to be zero length */
    if( iv_len == 0 ||
      ( (uint64_t) iv_len  ) >> 61 != 0 ||
      ( (uint64_t) add_len ) >> 61 != 0 )
    {
        return( MBEDTLS_ERR_GCM_BAD_INPUT );
    }

    memset( ctx->y, 0x00, sizeof(ctx->y) );
    memset( ctx->buf, 0x00, sizeof(ctx->buf) );

    ctx->mode = mode;
    ctx->len = 0;
    ctx->add_len = 0;

    if( iv_len == 12 )
    {
        memcpy( ctx->y, iv, iv_len );
        ctx->y[15] = 1;
    }
    else
    {
        memset( work_buf, 0x00, 16 );
        PUT_UINT32_BE( iv_len * 8, work_buf, 12 );

        p = iv;
        while( iv_len > 0 )
        {
            use_len = ( iv_len < 16 ) ? iv_len : 16;

            for( i = 0; i < use_len; i++ )
                ctx->y[i] ^= p[i];

            gcm_mult( ctx, ctx->y, ctx->y );

            iv_len -= use_len;
            p += use_len;
        }

        for( i = 0; i < 16; i++ )
            ctx->y[i] ^= work_buf[i];

        gcm_mult( ctx, ctx->y, ctx->y );
    }

    if( ( ret = nbedtls_cipher_update( &ctx->cipher_ctx, ctx->y,
                                       ctx->base_ectr ) ) != 0 )
    {
        return( ret );
    }

    ctx->add_len = add_len;
    p = add;
    while( add_len > 0 )
    {
        use_len = ( add_len < 16 ) ? add_len : 16;

        for( i = 0; i < use_len; i++ )
            ctx->buf[i] ^= p[i];

        gcm_mult( ctx, ctx->buf, ctx->buf );

        add_len -= use_len;
        p += use_len;
    }

    return( 0 );
}

int nbedtls_gcm_update( nbedtls_gcm_context *ctx,
                size_t length,
                const unsigned char *input,
                unsigned char *output )
{
    int ret;
    unsigned char ectr[16];
    size_t i;
    const unsigned char *p;
    unsigned char *out_p = output;
    size_t use_len;

    GCM_VALIDATE_RET( ctx != NULL );
    GCM_VALIDATE_RET( length == 0 || input != NULL );
    GCM_VALIDATE_RET( length == 0 || output != NULL );

    if( output > input && (size_t) ( output - input ) < length )
        return( MBEDTLS_ERR_GCM_BAD_INPUT );

    /* Total length is restricted to 2^39 - 256 bits, ie 2^36 - 2^5 bytes
     * Also check for possible overflow */
    if( ctx->len + length < ctx->len ||
        (uint64_t) ctx->len + length > 0xFFFFFFFE0ull )
    {
        return( MBEDTLS_ERR_GCM_BAD_INPUT );
    }

    ctx->len += length;

    p = input;
    while( length > 0 )
    {
        use_len = ( length < 16 ) ? length : 16;

        for( i = 16; i > 12; i-- )
            if( ++ctx->y[i - 1] != 0 )
                break;

        if( ( ret = nbedtls_cipher_update( &ctx->cipher_ctx, ctx->y, ectr
                                    ) ) != 0 )
        {
            return( ret );
        }

        for( i = 0; i < use_len; i++ )
        {
            if( ctx->mode == MBEDTLS_GCM_DECRYPT )
                ctx->buf[i] ^= p[i];
            out_p[i] = ectr[i] ^ p[i];
            if( ctx->mode == MBEDTLS_GCM_ENCRYPT )
                ctx->buf[i] ^= out_p[i];
        }

        gcm_mult( ctx, ctx->buf, ctx->buf );

        length -= use_len;
        p += use_len;
        out_p += use_len;
    }

    return( 0 );
}

int nbedtls_gcm_finish( nbedtls_gcm_context *ctx,
                unsigned char *tag,
                size_t tag_len )
{
    unsigned char work_buf[16];
    size_t i;
    uint64_t orig_len;
    uint64_t orig_add_len;

    GCM_VALIDATE_RET( ctx != NULL );
    GCM_VALIDATE_RET( tag != NULL );

    orig_len = ctx->len * 8;
    orig_add_len = ctx->add_len * 8;

    if( tag_len > 16 || tag_len < 4 )
        return( MBEDTLS_ERR_GCM_BAD_INPUT );

    memcpy( tag, ctx->base_ectr, tag_len );

    if( orig_len || orig_add_len )
    {
        memset( work_buf, 0x00, 16 );

        PUT_UINT32_BE( ( orig_add_len >> 32 ), work_buf, 0  );
        PUT_UINT32_BE( ( orig_add_len       ), work_buf, 4  );
        PUT_UINT32_BE( ( orig_len     >> 32 ), work_buf, 8  );
        PUT_UINT32_BE( ( orig_len           ), work_buf, 12 );

        for( i = 0; i < 16; i++ )
            ctx->buf[i] ^= work_buf[i];

        gcm_mult( ctx, ctx->buf, ctx->buf );

        for( i = 0; i < tag_len; i++ )
            tag[i] ^= ctx->buf[i];
    }

    return( 0 );
}

int nbedtls_gcm_crypt_and_tag( nbedtls_gcm_context *ctx,
                       int mode,
                       size_t length,
                       const unsigned char *iv,
                       size_t iv_len,
                       const unsigned char *add,
                       size_t add_len,
                       const unsigned char *input,
                       unsigned char *output,
                       size_t tag_len,
                       unsigned char *tag )
{
    int ret;

    GCM_VALIDATE_RET( ctx != NULL );
    GCM_VALIDATE_RET( iv != NULL );
    GCM_VALIDATE_RET( add_len == 0 || add != NULL );
    GCM_VALIDATE_RET( length == 0 || input != NULL );
    GCM_VALIDATE_RET( length == 0 || output != NULL );
    GCM_VALIDATE_RET( tag != NULL );

    if( ( ret = nbedtls_gcm_starts( ctx, mode, iv, iv_len, add, add_len ) ) != 0 )
        return( ret );

    if( ( ret = nbedtls_gcm_update( ctx, length, input, output ) ) != 0 )
        return( ret );

    if( ( ret = nbedtls_gcm_finish( ctx, tag, tag_len ) ) != 0 )
        return( ret );

    return( 0 );
}

int nbedtls_gcm_auth_decrypt( nbedtls_gcm_context *ctx,
                      size_t length,
                      const unsigned char *iv,
                      size_t iv_len,
                      const unsigned char *add,
                      size_t add_len,
                      const unsigned char *tag,
                      size_t tag_len,
                      const unsigned char *input,
                      unsigned char *output )
{
    int ret;
    unsigned char check_tag[16];
    size_t i;
    int diff;

    GCM_VALIDATE_RET( ctx != NULL );
    GCM_VALIDATE_RET( iv != NULL );
    GCM_VALIDATE_RET( add_len == 0 || add != NULL );
    GCM_VALIDATE_RET( tag != NULL );
    GCM_VALIDATE_RET( length == 0 || input != NULL );
    GCM_VALIDATE_RET( length == 0 || output != NULL );

    if( ( ret = nbedtls_gcm_crypt_and_tag( ctx, MBEDTLS_GCM_DECRYPT, length,
                                   iv, iv_len, add, add_len,
                                   input, output, tag_len, check_tag ) ) != 0 )
    {
        return( ret );
    }

    /* Check tag in "constant-time" */
    for( diff = 0, i = 0; i < tag_len; i++ )
        diff |= tag[i] ^ check_tag[i];

    if( diff != 0 )
    {
        nbedtls_platform_zeroize( output, length );
        return( MBEDTLS_ERR_GCM_AUTH_FAILED );
    }

    return( 0 );
}

void nbedtls_gcm_free( nbedtls_gcm_context *ctx )
{
    if( ctx == NULL )
        return;
    nbedtls_platform_zeroize( ctx, sizeof( nbedtls_gcm_context ) );
}

