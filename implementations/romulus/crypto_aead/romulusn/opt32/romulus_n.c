/**
 * Romulus-N core functions.
 * 
 * @author      Alexandre Adomnicai
 *              alex.adomnicai@gmail.com
 * 
 * @date        March 2022
 */
#include "romulus_n.h"

/**
 * Equivalent to 'memset(buf, 0x00, buflen)'.
 */
void zeroize(uint8_t buf[], int buflen)
{
  int i;
  for(i = 0; i < buflen; i++)
    buf[i] = 0x00;
}

/**
 * Equivalent to 'memcpy(dest, src, srclen)'.
 */
static void copy(uint8_t dest[], const uint8_t src[], int srclen)
{
  int i;
  for(i = 0; i < srclen; i++)
    dest[i] = src[i];
}

/**
 * TK1 and internale state are initialized to 0.
 */
void romulusn_init(uint8_t *state, uint8_t *tk1)
{
    tk1[0] = 0x01;
    zeroize(tk1+1, BLOCKBYTES-1);
    zeroize(state, BLOCKBYTES);
}

/**
 * Process the additional data and updates the internal state accordingly.
 */
void romulusn_process_ad(
    uint8_t *state, const uint8_t *ad, unsigned long long adlen,
    uint32_t *rtk_23, uint8_t *tk1, const uint8_t *npub, const uint8_t *k)
{
    int i;
    uint32_t tmp;
    uint32_t rtk_1[TKPERMORDER*BLOCKBYTES/4];
    uint8_t pad[BLOCKBYTES];
    if (adlen == 0) {
        UPDATE_CTR(tk1);
        SET_DOMAIN(tk1, 0x1A);
        tk_schedule_123(rtk_1, rtk_23, tk1, npub, k);
        skinny128_384_plus(state, state, rtk_1, rtk_23);
    } else {    // Process all double blocks except the last
        SET_DOMAIN(tk1, 0x08);
        while (adlen > 2*BLOCKBYTES) {
            UPDATE_CTR(tk1);
            XOR_BLOCK(state, state, ad);
            tk_schedule_123(rtk_1, rtk_23, tk1, ad + BLOCKBYTES, k);
            skinny128_384_plus(state, state, rtk_1, rtk_23);
            UPDATE_CTR(tk1);
            ad += 2*BLOCKBYTES;
            adlen -= 2*BLOCKBYTES;
        }
        //Pad and process the left-over blocks 
        UPDATE_CTR(tk1);
        if (adlen == 2*BLOCKBYTES) {        // Left-over complete double block
            XOR_BLOCK(state, state, ad);
            tk_schedule_123(rtk_1, rtk_23, tk1, ad + BLOCKBYTES, k);
            skinny128_384_plus(state, state, rtk_1, rtk_23);
            UPDATE_CTR(tk1);
            SET_DOMAIN(tk1, 0x18);
        } else if (adlen > BLOCKBYTES) {    //  Left-over partial double block
            adlen -= BLOCKBYTES;
            XOR_BLOCK(state, state, ad);
            copy(pad, ad + BLOCKBYTES, adlen);
            zeroize(pad + adlen, 15 - adlen);
            pad[15] = adlen;
            tk_schedule_123(rtk_1, rtk_23, tk1, pad, k);
            skinny128_384_plus(state, state, rtk_1, rtk_23);
            UPDATE_CTR(tk1);
            SET_DOMAIN(tk1, 0x1A);
        } else if (adlen == BLOCKBYTES) {   //  Left-over complete single block 
            XOR_BLOCK(state, state, ad);
            SET_DOMAIN(tk1, 0x18);
        } else {    // Left-over partial single block
            for(i = 0; i < (int)adlen; i++)
                state[i] ^= ad[i];
            state[15] ^= adlen;
            SET_DOMAIN(tk1, 0x1A);
        }
        tk_schedule_123(rtk_1, rtk_23, tk1, npub, k);
        skinny128_384_plus(state, state, rtk_1, rtk_23);
    }
}

/**
 * Process the message and updates the internal state as well as the output
 * buffer accordingly.
 */
void romulusn_process_msg(
    uint8_t *out, const uint8_t *in, unsigned long long inlen,
    uint8_t *state, const uint32_t *rtk_23, uint8_t *tk1, const int mode)
{
    int i;
    uint32_t tmp;
    uint8_t tmp_blk[BLOCKBYTES];
    uint32_t rtk_1[TKPERMORDER*BLOCKBYTES/4];
    zeroize(tk1, TWEAKEYBYTES);
    tk1[0] = 0x01;          //init the 56-bit LFSR counter
    if (inlen == 0) {
        UPDATE_CTR(tk1);
        SET_DOMAIN(tk1, 0x15);
        tk_schedule_1(rtk_1, tk1);
        skinny128_384_plus(state, state, rtk_1, rtk_23);
    } else {        //process all blocks except the last
        SET_DOMAIN(tk1, 0x04);
        while (inlen > BLOCKBYTES) {
            if(mode == ENCRYPT_MODE)
                RHO(state, out, in, tmp_blk);
            else
                RHO_INV(state, in, out, tmp_blk);
            UPDATE_CTR(tk1);
            tk_schedule_1(rtk_1, tk1);
            skinny128_384_plus(state, state, rtk_1, rtk_23);
            out     += BLOCKBYTES;
            in      += BLOCKBYTES;
            inlen   -= BLOCKBYTES;
        }
        // (eventually pad) and process the last block
        UPDATE_CTR(tk1);
        if (inlen < BLOCKBYTES) {
            if (mode == ENCRYPT_MODE) {
                for(i = 0; i < (int)inlen; i++) {
                    tmp = in[i];         //just in case 'in = out'
                    out[i] = in[i] ^ (state[i] >> 1) ^ (state[i] & 0x80) ^ (state[i] << 7);
                    state[i] ^= (uint8_t)tmp;
                }
            } else {
                for(i = 0; i < (int)inlen; i++) {
                    out[i] = in[i] ^ (state[i] >> 1) ^ (state[i] & 0x80) ^ (state[i] << 7);
                    state[i] ^= out[i];
                }
        }
            state[15] ^= (uint8_t)inlen; //padding
            SET_DOMAIN(tk1, 0x15);
        } else {
            if(mode == ENCRYPT_MODE)
                RHO(state, out, in, tmp_blk);
            else
                RHO_INV(state, in, out, tmp_blk);
            SET_DOMAIN(tk1, 0x14);
        }
        tk_schedule_1(rtk_1, tk1);
        skinny128_384_plus(state, state, rtk_1, rtk_23);
    }
}

/**
 * Generate the authentication tag from the internal state and copy it into the
 * output buffer 'c'.
 */
void romulusn_generate_tag(uint8_t *c, uint8_t *state)
{
    uint32_t tmp;
    G(state, state);
    copy(c, state, TAGBYTES);
}

/**
 * Verify the authentication tag from the internal state and the tag itself.
 * Returns a non-zero value if the verification fails.
 */
uint32_t romulusn_verify_tag(const uint8_t *tag, uint8_t *state)
{
    uint32_t tmp;
    G(state,state);
    tmp = 0;
    for(int i = 0; i < TAGBYTES; i++)
        tmp |= state[i] ^ tag[i];
    return tmp;
}
