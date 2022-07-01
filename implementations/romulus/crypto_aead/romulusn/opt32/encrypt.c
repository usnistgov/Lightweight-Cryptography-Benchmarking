/**
 * Romulus-N implementation following the SUPERCOP API.
 * 
 * @author      Alexandre Adomnicai
 *              alex.adomnicai@gmail.com
 * 
 * @date        March 2022
 */
#include "romulus_n.h"
#include "crypto_aead.h"

//Encryption and authentication using Romulus-N
int crypto_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    (void)nsec;
    uint8_t state[BLOCKBYTES];
    uint8_t tk1[TWEAKEYBYTES];
    uint32_t rtk_23[BLOCKBYTES*SKINNY128_384_ROUNDS/4];
    *clen = mlen + TAGBYTES;
    romulusn_init(state, tk1);
    romulusn_process_ad(state, ad, adlen, rtk_23, tk1, npub, k);
    romulusn_process_msg(c, m, mlen, state, rtk_23, tk1, ENCRYPT_MODE);
    zeroize((uint8_t *)rtk_23, sizeof(rtk_23));
    romulusn_generate_tag(c+mlen, state);
    return 0;
}

//Decryption and tag verification using Romulus-N
int crypto_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    (void)nsec;
    uint8_t tk1[TWEAKEYBYTES];
    uint8_t state[BLOCKBYTES];
    uint32_t rtk_23[BLOCKBYTES*SKINNY128_384_ROUNDS/4];

    if (clen < TAGBYTES)
        return -1;

    clen -= TAGBYTES;
    *mlen = clen;
    romulusn_init(state, tk1);
    romulusn_process_ad(state, ad, adlen, rtk_23, tk1, npub, k);
    romulusn_process_msg(m, c, clen, state, rtk_23, tk1, DECRYPT_MODE);
    zeroize((uint8_t *)rtk_23, sizeof(rtk_23));
    return romulusn_verify_tag(c+clen, state);
}
