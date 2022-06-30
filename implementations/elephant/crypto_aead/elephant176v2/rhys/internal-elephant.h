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

/*
 * The contents of this header file expand out to the full implementation of
 * Elephant for a specific underlying permutation.  We expect a number of
 * macros to be defined before this file is included to configure the
 * underlying Elephant variant:
 *
 * ELEPHANT_ALG_NAME    Name of the Elephant algorithm; e.g. dumbo
 * ELEPHANT_STATE_SIZE  Size of the permutation state.
 * ELEPHANT_STATE       Permutation state type; e.g. keccakp_200_state_t
 * ELEPHANT_KEY_SIZE    Size of the key
 * ELEPHANT_NONCE_SIZE  Size of the nonce
 * ELEPHANT_TAG_SIZE    Size of the tag
 * ELEPHANT_LFSR        Name of the LFSR function; e.g. dumbo_lfsr
 * ELEPHANT_PERMUTE     Name of the permutation function
 */
#if defined(ELEPHANT_ALG_NAME)

#define ELEPHANT_CONCAT_INNER(name,suffix) name##suffix
#define ELEPHANT_CONCAT(name,suffix) ELEPHANT_CONCAT_INNER(name,suffix)

static int ELEPHANT_CONCAT(ELEPHANT_ALG_NAME,_aead_crypt)
    (unsigned char *c, const unsigned char *m, size_t mlen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub, const unsigned char *k,
     int encrypt)
{
    unsigned char *cstart = c;
    size_t clen = mlen;
    ELEPHANT_STATE state;
    unsigned char start[ELEPHANT_STATE_SIZE];
    unsigned char mask1[ELEPHANT_STATE_SIZE];
    unsigned char mask2[ELEPHANT_STATE_SIZE];
    unsigned char mask3[ELEPHANT_STATE_SIZE];
    unsigned char tag[ELEPHANT_STATE_SIZE];
    unsigned char *m0;
    unsigned char *m1 = mask1;
    unsigned char *m2 = mask2;
    unsigned char *m3 = mask3;
    int admore, mmore;

    /* Hash the key and generate the starting mask */
    memcpy(state.B, k, ELEPHANT_KEY_SIZE);
    memset(state.B + ELEPHANT_KEY_SIZE, 0, sizeof(state.B) - ELEPHANT_KEY_SIZE);
    ELEPHANT_PERMUTE(&state);
    memcpy(start, state.B, ELEPHANT_STATE_SIZE);

    /* Compute the initial 0, 1, and 2 mask values */
    memcpy(m1, start, ELEPHANT_STATE_SIZE);
    ELEPHANT_LFSR(m2, m1);
    ELEPHANT_LFSR(m3, m2);

    /* The initial tag is the nonce concatenated with the first block of ad */
    memcpy(tag, npub, ELEPHANT_NONCE_SIZE);
    if (adlen >= (ELEPHANT_STATE_SIZE - ELEPHANT_NONCE_SIZE)) {
        memcpy(tag + ELEPHANT_NONCE_SIZE, ad,
               ELEPHANT_STATE_SIZE - ELEPHANT_NONCE_SIZE);
        ad += ELEPHANT_STATE_SIZE - ELEPHANT_NONCE_SIZE;
        adlen -= ELEPHANT_STATE_SIZE - ELEPHANT_NONCE_SIZE;
        admore = 1;
    } else {
        memcpy(tag + ELEPHANT_NONCE_SIZE, ad, adlen);
        tag[ELEPHANT_NONCE_SIZE + adlen] = 0x01;
        memset(tag + ELEPHANT_NONCE_SIZE + adlen + 1, 0,
               ELEPHANT_STATE_SIZE - ELEPHANT_NONCE_SIZE - (adlen + 1));
        admore = 0;
        adlen = 0;
    }

    /* Process associated data and message blocks until we are out */
    mmore = 1;
    for (;;) {
        /* Encrypt or decrypt the next message block */
        if (mmore) {
            if (encrypt) {
                /* Encrypt the plaintext message block */
                lw_xor_block_2_src(state.B, npub, m1, ELEPHANT_NONCE_SIZE);
                memcpy(state.B + ELEPHANT_NONCE_SIZE, m1 + ELEPHANT_NONCE_SIZE,
                       ELEPHANT_STATE_SIZE - ELEPHANT_NONCE_SIZE);
                lw_xor_block(state.B, m2, ELEPHANT_STATE_SIZE);
                ELEPHANT_PERMUTE(&state);
                lw_xor_block(state.B, m1, ELEPHANT_STATE_SIZE);
                lw_xor_block(state.B, m2, ELEPHANT_STATE_SIZE);
                if (mlen >= ELEPHANT_STATE_SIZE) {
                    lw_xor_block_2_dest(c, state.B, m, ELEPHANT_STATE_SIZE);
                    c += ELEPHANT_STATE_SIZE;
                    m += ELEPHANT_STATE_SIZE;
                    mlen -= ELEPHANT_STATE_SIZE;
                } else {
                    lw_xor_block_2_dest(c, state.B, m, mlen);
                    state.B[mlen] = 0x01;
                    memset(state.B + mlen + 1, 0,
                           ELEPHANT_STATE_SIZE - mlen - 1);
                    c += mlen;
                    m += mlen;
                    mlen = 0;
                    mmore = 0;
                }

                /* Authenticate the outgoing ciphertext message block */
                lw_xor_block(state.B, m1, ELEPHANT_STATE_SIZE);
                lw_xor_block(state.B, m3, ELEPHANT_STATE_SIZE);
                ELEPHANT_PERMUTE(&state);
                lw_xor_block(state.B, m1, ELEPHANT_STATE_SIZE);
                lw_xor_block(state.B, m3, ELEPHANT_STATE_SIZE);
                lw_xor_block(tag, state.B, ELEPHANT_STATE_SIZE);
            } else {
                /* Authenticate the incoming ciphertext message block */
                if (mlen >= ELEPHANT_STATE_SIZE) {
                    lw_xor_block_2_src(state.B, m, m1, ELEPHANT_STATE_SIZE);
                } else {
                    memcpy(state.B, m, mlen);
                    state.B[mlen] = 0x01;
                    memset(state.B + mlen + 1, 0,
                           ELEPHANT_STATE_SIZE - mlen - 1);
                    lw_xor_block(state.B, m1, ELEPHANT_STATE_SIZE);
                }
                lw_xor_block(state.B, m3, ELEPHANT_STATE_SIZE);
                ELEPHANT_PERMUTE(&state);
                lw_xor_block(state.B, m1, ELEPHANT_STATE_SIZE);
                lw_xor_block(state.B, m3, ELEPHANT_STATE_SIZE);
                lw_xor_block(tag, state.B, ELEPHANT_STATE_SIZE);

                /* Decrypt the ciphertext message block */
                lw_xor_block_2_src(state.B, npub, m1, ELEPHANT_NONCE_SIZE);
                memcpy(state.B + ELEPHANT_NONCE_SIZE, m1 + ELEPHANT_NONCE_SIZE,
                       ELEPHANT_STATE_SIZE - ELEPHANT_NONCE_SIZE);
                lw_xor_block(state.B, m2, ELEPHANT_STATE_SIZE);
                ELEPHANT_PERMUTE(&state);
                lw_xor_block(state.B, m1, ELEPHANT_STATE_SIZE);
                lw_xor_block(state.B, m2, ELEPHANT_STATE_SIZE);
                if (mlen >= ELEPHANT_STATE_SIZE) {
                    lw_xor_block_2_src(c, state.B, m, ELEPHANT_STATE_SIZE);
                    c += ELEPHANT_STATE_SIZE;
                    m += ELEPHANT_STATE_SIZE;
                    mlen -= ELEPHANT_STATE_SIZE;
                } else {
                    lw_xor_block_2_src(c, state.B, m, mlen);
                    c += mlen;
                    m += mlen;
                    mlen = 0;
                    mmore = 0;
                }
            }
        }

        /* Authenticate the next associated data block */
        if (admore) {
            if (adlen >= ELEPHANT_STATE_SIZE) {
                lw_xor_block_2_src(state.B, ad, m2, ELEPHANT_STATE_SIZE);
                ad += ELEPHANT_STATE_SIZE;
                adlen -= ELEPHANT_STATE_SIZE;
            } else {
                memcpy(state.B, ad, adlen);
                state.B[adlen] = 0x01;
                memset(state.B + adlen + 1, 0, ELEPHANT_STATE_SIZE - adlen - 1);
                lw_xor_block(state.B, m2, ELEPHANT_STATE_SIZE);
                admore = 0;
                adlen = 0;
            }
            ELEPHANT_PERMUTE(&state);
            lw_xor_block(state.B, m2, ELEPHANT_STATE_SIZE);
            lw_xor_block(tag, state.B, ELEPHANT_STATE_SIZE);
        }

        /* Bail out if no more blocks to be processed */
        if (!admore && !mmore)
            break;

        /* Rotate the masks */
        m0 = m1;
        m1 = m2;
        m2 = m3;
        m3 = m0;
        ELEPHANT_LFSR(m3, m2);
    }

    /* Compute the authentication tag */
    lw_xor_block_2_src(state.B, tag, start, ELEPHANT_STATE_SIZE);
    ELEPHANT_PERMUTE(&state);
    if (encrypt) {
        lw_xor_block_2_src(c, state.B, start, ELEPHANT_TAG_SIZE);
        return 0;
    } else {
        lw_xor_block(state.B, start, ELEPHANT_TAG_SIZE);
        return aead_check_tag(cstart, clen, state.B, m, ELEPHANT_TAG_SIZE);
    }
}

int ELEPHANT_CONCAT(ELEPHANT_ALG_NAME,_aead_encrypt)
    (unsigned char *c, size_t *clen,
     const unsigned char *m, size_t mlen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    /* Set the length of the returned ciphertext */
    *clen = mlen + ELEPHANT_TAG_SIZE;

    /* Encrypt the message and authenticate it */
    return ELEPHANT_CONCAT(ELEPHANT_ALG_NAME,_aead_crypt)
        (c, m, mlen, ad, adlen, npub, k, 1);
}

int ELEPHANT_CONCAT(ELEPHANT_ALG_NAME,_aead_decrypt)
    (unsigned char *m, size_t *mlen,
     const unsigned char *c, size_t clen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < ELEPHANT_TAG_SIZE)
        return -1;
    clen -= ELEPHANT_TAG_SIZE;
    *mlen = clen;

    /* Decrypt the message and authenticate it */
    return ELEPHANT_CONCAT(ELEPHANT_ALG_NAME,_aead_crypt)
        (m, c, clen, ad, adlen, npub, k, 0);
}

#endif /* ELEPHANT_ALG_NAME */

/* Now undefine everything so that we can include this file again for
 * another variant on the Elephant algorithm */
#undef ELEPHANT_ALG_NAME
#undef ELEPHANT_STATE_SIZE
#undef ELEPHANT_STATE
#undef ELEPHANT_KEY_SIZE
#undef ELEPHANT_NONCE_SIZE
#undef ELEPHANT_TAG_SIZE
#undef ELEPHANT_LFSR
#undef ELEPHANT_PERMUTE
#undef ELEPHANT_CONCAT
#undef ELEPHANT_CONCAT_INNER
