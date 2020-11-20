#include <stdio.h>
#include <stdlib.h>

#include "crypto_aead.h"
#include "api.h"
#include "SimP_256.h"

#define rate_size 16
#define state_size 32
#define mask_size 8

/*
#############################################################################################################
################################ Oribatida Partial Block Padding (10*) Module ###############################
#############################################################################################################
*/

int pad_1_0(u8 *value, u8 *value_new, ull length, ull length_new)
{
    // local variable declaration
    ull i = 0;


    if(length == 0)                                  // when associated data or message is empty
        return 0;


    else if(length == length_new)                    // when last block of associated data or message is full
    {
        for(i = 0; i < length; i++)
            value_new[i] = value[i];

        return 0;
    }


    else                                             // when last block of associated data or message is partial
    {
        for(i = 0; i < length; i++)
            value_new[i] = value[i];

        value_new[length] = 128;                     // adds 1 followed by zeros

        for(i = 0; i < length_new - length - 1; i++)
            value_new[length + 1 + i] = 0;           // continues adding zeros until the last block is full

        return 0;
    }
}

/*
#############################################################################################################
################################ Oribatida Domain Constants Generation Module ###############################
#############################################################################################################
*/

int get_domain(ull *constant, ull adlen, ull mlen)
{
    // calculates the value of d_n
    if(adlen == 0 && mlen == 0)                    // case 1: when both associated data and message are empty
        constant[0] = 9;

    else                                           // case 2: when associated data is non-empty
        constant[0] = 5;


    // calculates the value of d_a
    if(adlen % rate_size == 0 && mlen != 0)        // case 1: when message is non-empty, and last block of associated data is full
        constant[1] = 4;

    else if(adlen % rate_size != 0 && mlen != 0)   // case 2: when message is non-empty, and last block of associated data is partial
        constant[1] = 6;

    else if(adlen % rate_size == 0 && mlen == 0)   // case 3: when message is empty, and last block of associated data is full
        constant[1] = 12;

    else if(adlen % rate_size != 0 && mlen == 0)   // case 4: when message is empty, and last block of associated data is partial
        constant[1] = 14;


    // calculates the value of d_e
    if(mlen % rate_size == 0)         // case 1: when last block of message is full
        constant[2] = 13;

    else if(mlen % rate_size != 0)    // case 2: when last block of message is partial
        constant[2] = 15;


    return 0;
}

/*
#############################################################################################################
####################################### Oribatida IV Generation Module ######################################
#############################################################################################################
*/

int generate_iv(u8 *k, u8 *npub, u8 *state, ull d_n)
{
    // local variable declaration
    ull i = 0;


    for(i = 0; i < CRYPTO_NPUBBYTES; i++)                 // The first part of the IV is the nonce.
        state[i] = npub[i];


    for(i = 0; i < CRYPTO_KEYBYTES; i++)                  // The remaining part of the IV is the key.
        state[i + CRYPTO_NPUBBYTES] = k[i];


    state[state_size - 1] = state[state_size - 1] ^ d_n;  // Domain constant is XOR-ed with the last byte of the state.


    return 0;
}

/*
#############################################################################################################
################################# Oribatida Associated Data Processing Module ###############################
#############################################################################################################
*/

int process_ad(u8 *ad, ull adlen, u8 *state, ull d_a)
{
    // local variable declaration
    ull i = 0, j = 0;


    if(adlen > 0)
    {
        for(i = 0; i < (adlen / rate_size) - 1; i++)                                // All but last block is absorbed here.
        {
            for(j = 0; j < rate_size; j++)
                state[j] = state[j] ^ ad[(i * rate_size) + j];

            SimP_2(state);                                                          // SimP_2 call after absorption of each block
        }


        for(j = 0; j < rate_size; j++)                                              // Last block is absorbed here.
            state[j] = state[j] ^ ad[(((adlen / rate_size) - 1) * rate_size) + j];


        state[state_size - 1] = state[state_size - 1] ^ d_a;         // Domain constant is XOR-ed with the last byte of the state.


        SimP_4(state);                                                              // SimP_4 call after absorption of last block
    }


    return 0;
}

/*
#############################################################################################################
################################### Oribatida Plaintext Processing Module ###################################
#############################################################################################################
*/

int process_m(u8 *m, ull mlen, u8 *c, ull *clen, u8 *state, u8 *mask, ull d_e)
{
    // local variable declaration
    ull mlen_new = 0, i = 0, j = 0;


    *clen = 0;                                                            // Initializing 'clen' counter with 0


    // Length of the plaintext is updated.
    if(mlen % rate_size != 0)
        mlen_new = mlen + (rate_size - (mlen % rate_size));

    else
        mlen_new = mlen;


    if(mlen_new > 0)
        // Each block is processed here.
        for(i = 0; i < mlen_new / rate_size; i++)
        {
            // Each byte of the current block is processed here.
            for(j = 0; j < rate_size; j++)
            {
                state[j] = state[j] ^ m[(i * rate_size) + j];             // Plaintext bytes are absobed.

                if(*clen < mlen)
                    c[(i * rate_size) + j] = state[j];                    // Ciphertext bytes are generated.

                if(rate_size - j < mask_size + 1)
                {
                    if(*clen < mlen)
                        c[(i * rate_size) + j] = c[(i * rate_size) + j] 
                                                 ^ mask[j - rate_size + mask_size];      // Mask is XOR-ed with the ciphertext.

                    mask[j - rate_size + mask_size] = state[j - rate_size + state_size]; // Mask is updated.
                }

                if(*clen < mlen)
                    *clen = *clen + 1;                                    // 'clen' counter is updated.
            }

            if(i == (mlen_new / rate_size) - 1)
                state[state_size - 1] = state[state_size - 1] ^ d_e;      // Domain constant is XOR-ed with the last byte of the state.

            SimP_4(state);                                                // SimP_4 call after absorption of each block
        }


    for(i = 0; i < CRYPTO_ABYTES; i++)                                    // Tag is generated here.
    {
        c[mlen + i] = state[i];

        *clen = *clen + 1;                                                // 'clen' counter is updated.
    }


    return 0;
}

/*
#############################################################################################################
################################## Oribatida Ciphertext Processing Module ###################################
#############################################################################################################
*/

ull process_c(u8 *m, ull *mlen, u8 *c, ull clen, u8 *state, u8 *mask, ull d_e)
{
    // local variable declaration
    u8 *c_new = 0;
    ull i = 0, j = 0, clen_new = 0;


    *mlen = 0;                                                                   // Initializing 'mlen' counter with 0


    // Length of the ciphertext is updated.
    if((clen - CRYPTO_ABYTES) % rate_size != 0)
        clen_new = clen - CRYPTO_ABYTES + (rate_size - ((clen - CRYPTO_ABYTES) % rate_size));

    else
        clen_new = clen - CRYPTO_ABYTES;


    c_new = (u8 *)malloc(clen_new * sizeof(u8));


    for(i = 0; i < clen_new; i++)
        c_new[i] = c[i];


    if(clen_new > rate_size)
        // All but last block is processed here.
        for(i = 0; i < (clen_new / rate_size) - 1; i++)
        {
            // Each byte of the current block is processed here.
            for(j = 0; j < rate_size; j++)
            {
                m[(i * rate_size) + j] = state[j] ^ c_new[(i * rate_size) + j];  // Ciphertext bytes are absorbed.

                state[j] = c_new[(i * rate_size) + j];                           // State is updated to an intermediate value.

                if(rate_size - j < mask_size + 1)
                {
                    m[(i * rate_size) + j] = m[(i * rate_size) + j] ^ mask[j - rate_size + mask_size]; // Plaintext bytes are generated.

                    state[j] = state[j] ^ mask[j - rate_size + mask_size];       // State is updated to its final value.

                    mask[j - rate_size + mask_size] = state[j - rate_size + state_size];               // Mask is updated.
                }

                *mlen = *mlen + 1;                                               // 'mlen' counter is updated.
            }

            SimP_4(state);                                                       // SimP_4 call after absorption of each block
        }


    if(clen_new > 0)
    {
        if(clen % rate_size != 0)
        {
            i = rate_size - (clen % rate_size);                                  // size of ciphertext pad is calculated.

            // padding of the last block is done here.
            for(j = 0; j < i; j++)
            {
                c_new[clen_new - i + j] = state[rate_size - i + j];

                if(j == 0)
                    c_new[clen_new - i + j] = c_new[clen_new - i + j] ^ 128;

                if(i - j < mask_size + 1)
                    c_new[clen_new - i + j] = c_new[clen_new - i + j] ^ mask[mask_size - i + j];
            }
        }

        // Each byte of the last block is processed here.
        for(j = 0; j < rate_size; j++)
        {
            if(*mlen < clen - rate_size)
                m[(((clen_new / rate_size) - 1) * rate_size) + j] = state[j] ^ c_new[(((clen_new / rate_size) - 1) * rate_size) + j];

            state[j] = c_new[(((clen_new / rate_size) - 1) * rate_size) + j];

            if(rate_size - j < mask_size + 1)
            {
                if(*mlen < clen - rate_size)
                    m[(((clen_new / rate_size) - 1) * rate_size) + j] = m[(((clen_new / rate_size) - 1) * rate_size) + j] 
                                                                        ^ mask[j - rate_size + mask_size];
                state[j] = state[j] ^ mask[j - rate_size + mask_size];

                mask[j - rate_size + mask_size] = state[j - rate_size + state_size];
            }

            if(*mlen < clen - CRYPTO_ABYTES)
                *mlen = *mlen + 1;
        }
        state[state_size - 1] = state[state_size - 1] ^ d_e;  // Domain constant is XOR-ed with the last byte of the state.

        SimP_4(state);                                        // SimP_4 call after absorption of each block
    }


    j = 0;


    // Tag verification is done here.
    for(i = 0; i < CRYPTO_ABYTES; i++)
        if(c[clen - CRYPTO_ABYTES + i] != state[i])
            j++;


    // releasing memory which were allocated dynamically
    free(c_new);


    if(j > 0)
        return -1;  // In case of verification failure

    else
        return 0;   // In case os verification success
}

/*
#############################################################################################################
######################################## Oribatida Encryption Module ########################################
#############################################################################################################
*/

int crypto_aead_encrypt(unsigned char *c,
                        unsigned long long *clen,
                        const unsigned char *m,
                        unsigned long long mlen,
                        const unsigned char *ad,
                        unsigned long long adlen,
                        const unsigned char *nsec,
                        const unsigned char *npub,
                        const unsigned char *k)
{
    // local variable declaration
    u8 *state = 0, *mask = 0, *ad_new = 0, *m_new = 0;
    ull constant[3] = {0}, adlen_new = 0, mlen_new = 0, i = 0;


    if(nsec == 0){;}


    *clen = 0;                                                    // Initializing 'clen' counter with 0


    get_domain(constant, adlen, mlen);                            // Call to Domain Constants Generation Module


    state = (u8 *)malloc(state_size * sizeof(u8));                // creating state array


    generate_iv((u8 *)k, (u8 *)npub, state, constant[0]);         // Call to IV Generation Module


    mask = (u8 *)malloc(mask_size * sizeof(u8));                  // creating mask array


    // Mask is updated here, if associated data is empty.
    if(adlen == 0)
        for(i = 0; i < mask_size; i++)
            mask[i] = state[state_size - mask_size + i];

    // We don't include the domain constant into the mask.
    mask[mask_size - 1] = mask[mask_size - 1] ^ constant[0];


    SimP_4(state);                                                 // SimP_4 call with the IV


    // Mask is updated here, if associated data is non-empty.
    if(adlen != 0)
        for(i = 0; i < mask_size; i++)
            mask[i] = state[state_size - mask_size + i];


    if(adlen % rate_size == 0)
        adlen_new = adlen;

    else
        adlen_new = adlen + (rate_size - (adlen % rate_size));


    ad_new = (u8 *)malloc(adlen_new * sizeof(u8));


    pad_1_0((u8 *)ad, ad_new, adlen, adlen_new);                   // Call to Partial Block Padding (10*) Module with associated data


    process_ad(ad_new, adlen_new, state, constant[1]);             // Call to Associated Data Processing Module


    if(mlen % rate_size == 0)
        mlen_new = mlen;

    else
        mlen_new = mlen + (rate_size - (mlen % rate_size));


    m_new = (u8 *)malloc(mlen_new * sizeof(u8));


    pad_1_0((u8 *)m, m_new, mlen, mlen_new);                       // Call to Partial Block Padding (10*) Module with plaintext


    process_m(m_new, mlen, c, clen, state, mask, constant[2]);     // Call to Plaintext Processing Module


    // releasing memory which were allocated dynamically
    free(state);
    free(mask);
    free(ad_new);
    free(m_new);


    return 0;
}

/*
#############################################################################################################
######################################## Oribatida Decryption Module ########################################
#############################################################################################################
*/

int crypto_aead_decrypt(unsigned char *m,
                        unsigned long long *mlen,
                        unsigned char *nsec,
                        const unsigned char *c,
                        unsigned long long clen,
                        const unsigned char *ad,
                        unsigned long long adlen,
                        const unsigned char *npub,
                        const unsigned char *k)
{
    // local variable declaration
    u8 *state = 0, *mask = 0, *ad_new = 0;
    ull constant[3] = {0}, adlen_new = 0, i = 0;


    if(nsec == 0){;}


    *mlen = 0;                                                          // Initializing 'mlen' counter with 0


    get_domain(constant, adlen, clen - CRYPTO_ABYTES);                  // Call to Domain Constants Generation Module


    state = (u8 *)malloc(state_size * sizeof(u8));                      // creating state array


    generate_iv((u8 *)k, (u8 *)npub, state, constant[0]);               // Call to IV Generation Module


    mask = (u8 *)malloc(mask_size * sizeof(u8));                        // creating mask array


    // Mask is updated here, if associated data is empty.
    if(adlen == 0)
        for(i = 0; i < mask_size; i++)
            mask[i] = state[state_size - mask_size + i];

    // We don't include the domain constant into the mask.
    mask[mask_size - 1] = mask[mask_size - 1] ^ constant[0];


    SimP_4(state);                                                       // SimP_4 call with the IV


    // Mask is updated here, if associated data is non-empty.
    if(adlen != 0)
        for(i = 0; i < mask_size; i++)
            mask[i] = state[state_size - mask_size + i];


    if(adlen % rate_size == 0)
        adlen_new = adlen;

    else
        adlen_new = adlen + (rate_size - (adlen % rate_size));


    ad_new = (u8 *)malloc(adlen_new * sizeof(u8));


    pad_1_0((u8 *)ad, ad_new, adlen, adlen_new);                         // Call to Partial Block Padding (10*) Module with associated data


    process_ad(ad_new, adlen_new, state, constant[1]);                   // Call to Associated Data Processing Module


    i = process_c(m, mlen, (u8 *)c, clen, state, mask, constant[2]);     // Call to Ciphertext Processing Module


    // releasing memory which were allocated dynamically
    free(state);
    free(mask);
    free(ad_new);


    return i;
}
