#include <stdio.h>
#include <string.h>
#include "api.h"
#include "isap.h"
#include "KeccakP-400-64.macros"
#include "KeccakP-400-unrolling.macros"

const UINT8 ISAP_IV1[] = {0x01,ISAP_K,ISAP_rH,ISAP_rB,ISAP_sH,ISAP_sB,ISAP_sE,ISAP_sK};
const UINT8 ISAP_IV2[] = {0x02,ISAP_K,ISAP_rH,ISAP_rB,ISAP_sH,ISAP_sB,ISAP_sE,ISAP_sK};
const UINT8 ISAP_IV3[] = {0x03,ISAP_K,ISAP_rH,ISAP_rB,ISAP_sH,ISAP_sB,ISAP_sE,ISAP_sK};

union Lane {
    UINT8 l8[18];
    UINT16 l16[9];
    UINT64 l64[2]; // incomplete
};

union State {
    UINT8 l8[50];
    UINT16 l16[25];
    UINT64 l64[6]; // incomplete
    struct {
        UINT16 Aba;
        UINT16 Abe;
        UINT16 Abi;
        UINT16 Abo;
        UINT16 Abu;
        UINT16 Aga;
        UINT16 Age;
        UINT16 Agi;
        UINT16 Ago;
        UINT16 Agu;
        UINT16 Aka;
        UINT16 Ake;
        UINT16 Aki;
        UINT16 Ako;
        UINT16 Aku;
        UINT16 Ama;
        UINT16 Ame;
        UINT16 Ami;
        UINT16 Amo;
        UINT16 Amu;
        UINT16 Asa;
        UINT16 Ase;
        UINT16 Asi;
        UINT16 Aso;
        UINT16 Asu;
    } X;
};

#define PermuteRoundsBX rounds1X
#define PermuteRoundsEX rounds8X
#define PermuteRoundsHX rounds16X
#define PermuteRoundsKX rounds8X

#define ABSORB_MAC(src, len) ({ \
    size_t rem_bytes = len; \
    size_t idx = 0; \
    while(1){ \
        if(rem_bytes>ISAP_rH_SZ){ \
            S.l64[0] ^= *((UINT64 *)(src+idx+0)); \
            S.l64[1] ^= *((UINT64 *)(src+idx+8)); \
            S.l16[8] ^= *((UINT64 *)(src+idx+16)); \
            idx += ISAP_rH_SZ; \
            rem_bytes -= ISAP_rH_SZ; \
            PermuteRoundsHX; \
        } else if(rem_bytes==ISAP_rH_SZ){ \
            S.l64[0] ^= *((UINT64 *)(src+idx+0)); \
            S.l64[1] ^= *((UINT64 *)(src+idx+8)); \
            S.l16[8] ^= *((UINT64 *)(src+idx+16)); \
            PermuteRoundsHX; \
            S.X.Aba ^= 0x80ULL; \
            PermuteRoundsHX; \
            break; \
        } else { \
           for (size_t i = 0; i < ISAP_rH_SZ; i++) { \
               if(i < rem_bytes){ \
                   S.l8[i] ^= src[idx]; \
                   idx++; \
               } else if(i==rem_bytes){ \
                   S.l8[i] ^= 0x80; \
               } \
           } \
           PermuteRoundsHX; \
           break; \
       } \
   } \
})

/******************************************************************************/
/*                                   IsapRk                                   */
/******************************************************************************/

void isap_rk(
	const UINT8 *k,
	const UINT8 *iv,
	const UINT8 *y,
	const UINT64 ylen,
	UINT8 *out,
	const UINT64 outlen
){
    const UINT16 *k16 = (UINT16 *)k;
    const UINT16 *iv16 = (UINT16 *)iv;
    UINT16 *out16 = (UINT16 *)out;

    // Init state
    declareABCDEX
    S.X.Aba = k16[0];
    S.X.Abe = k16[1];
    S.X.Abi = k16[2];
    S.X.Abo = k16[3];
    S.X.Abu = k16[4];
    S.X.Aga = k16[5];
    S.X.Age = k16[6];
    S.X.Agi = k16[7];
    S.X.Ago = iv16[0];
    S.X.Agu = iv16[1];
    S.X.Aka = iv16[2];
    S.X.Ake = iv16[3];
    S.X.Aki = 0;
    S.X.Ako = 0;
    S.X.Aku = 0;
    S.X.Ama = 0;
    S.X.Ame = 0;
    S.X.Ami = 0;
    S.X.Amo = 0;
    S.X.Amu = 0;
    S.X.Asa = 0;
    S.X.Ase = 0;
    S.X.Asi = 0;
    S.X.Aso = 0;
    S.X.Asu = 0;
    PermuteRoundsKX;

    // Absorb all bits of Y
    for (UINT64 i = 0; i < ylen*8-1; i++){
        size_t cur_byte_pos = i/8;
        size_t cur_bit_pos = 7-(i%8);
        UINT16 cur_bit = ((y[cur_byte_pos] >> (cur_bit_pos)) & 0x01) << 7;
        S.X.Aba ^= cur_bit;
        PermuteRoundsBX;
    }
    UINT16 cur_bit = ((y[ylen-1]) & 0x01) << 7;
    S.X.Aba ^= cur_bit;
    PermuteRoundsKX;

    // Extract K*
    out16[0] = S.X.Aba;
    out16[1] = S.X.Abe;
    out16[2] = S.X.Abi;
    out16[3] = S.X.Abo;
    out16[4] = S.X.Abu;
    out16[5] = S.X.Aga;
    out16[6] = S.X.Age;
    out16[7] = S.X.Agi;
    if(outlen == ISAP_STATE_SZ-CRYPTO_NPUBBYTES){
        out16[8] = S.X.Ago;
        out16[9] = S.X.Agu;
        out16[10] = S.X.Aka;
        out16[11] = S.X.Ake;
        out16[12] = S.X.Aki;
        out16[13] = S.X.Ako;
        out16[14] = S.X.Aku;
        out16[15] = S.X.Ama;
        out16[16] = S.X.Ame;
    }
}

/******************************************************************************/
/*                                  IsapMac                                   */
/******************************************************************************/

void isap_mac(
    const UINT8 *k,
    const UINT8 *npub,
    const UINT8 *ad, const UINT64 adlen,
    const UINT8 *c, const UINT64 clen,
    UINT8 *tag
){
    const UINT16 *npub16 = (UINT16 *)npub;

    // Init state
    declareABCDEX
    S.X.Aba = npub16[0];
    S.X.Abe = npub16[1];
    S.X.Abi = npub16[2];
    S.X.Abo = npub16[3];
    S.X.Abu = npub16[4];
    S.X.Aga = npub16[5];
    S.X.Age = npub16[6];
    S.X.Agi = npub16[7];
    S.X.Ago = ISAP_IV1[0] | (ISAP_IV1[1] << 8);
    S.X.Agu = ISAP_IV1[2] | (ISAP_IV1[3] << 8);
    S.X.Aka = ISAP_IV1[4] | (ISAP_IV1[5] << 8);
    S.X.Ake = ISAP_IV1[6] | (ISAP_IV1[7] << 8);
    S.X.Aki = 0;
    S.X.Ako = 0;
    S.X.Aku = 0;
    S.X.Ama = 0;
    S.X.Ame = 0;
    S.X.Ami = 0;
    S.X.Amo = 0;
    S.X.Amu = 0;
    S.X.Asa = 0;
    S.X.Ase = 0;
    S.X.Asi = 0;
    S.X.Aso = 0;
    S.X.Asu = 0;
    PermuteRoundsHX;

    // Absorb AD
    ABSORB_MAC(ad,adlen);

    // Domain seperation
    S.X.Asu ^= 0x0100;

    // Absorb C
    ABSORB_MAC(c,clen);

    // Derive K*
    UINT16 y[8];
    y[0] = (UINT16) S.X.Aba;
    y[1] = (UINT16) S.X.Abe;
    y[2] = (UINT16) S.X.Abi;
    y[3] = (UINT16) S.X.Abo;
    y[4] = (UINT16) S.X.Abu;
    y[5] = (UINT16) S.X.Aga;
    y[6] = (UINT16) S.X.Age;
    y[7] = (UINT16) S.X.Agi;
    isap_rk(k, ISAP_IV2, (UINT8 *)y, CRYPTO_KEYBYTES, (UINT8 *)y, CRYPTO_KEYBYTES);
    S.X.Aba = y[0];
    S.X.Abe = y[1];
    S.X.Abi = y[2];
    S.X.Abo = y[3];
    S.X.Abu = y[4];
    S.X.Aga = y[5];
    S.X.Age = y[6];
    S.X.Agi = y[7];

    // Squeeze tag
    PermuteRoundsHX;

    UINT16 *tag16 = (UINT16 *)tag;
    tag16[0] = S.X.Aba;
    tag16[1] = S.X.Abe;
    tag16[2] = S.X.Abi;
    tag16[3] = S.X.Abo;
    tag16[4] = S.X.Abu;
    tag16[5] = S.X.Aga;
    tag16[6] = S.X.Age;
    tag16[7] = S.X.Agi;
}

/******************************************************************************/
/*                                  IsapEnc                                   */
/******************************************************************************/

void isap_enc(
	const UINT8 *k,
	const UINT8 *npub,
	const UINT8 *m,
    const UINT64 mlen,
	UINT8 *c
){
    // Derive session key
    UINT8 state[ISAP_STATE_SZ];
    isap_rk(k,ISAP_IV3,npub,CRYPTO_NPUBBYTES,state,ISAP_STATE_SZ-CRYPTO_NPUBBYTES);
    UINT16 *state16 = (UINT16 *)state;
    UINT16 *npub16 = (UINT16 *)npub;

    // Init state
    declareABCDEX
    S.X.Aba = state16[0];
    S.X.Abe = state16[1];
    S.X.Abi = state16[2];
    S.X.Abo = state16[3];
    S.X.Abu = state16[4];
    S.X.Aga = state16[5];
    S.X.Age = state16[6];
    S.X.Agi = state16[7];
    S.X.Ago = state16[8];
    S.X.Agu = state16[9];
    S.X.Aka = state16[10];
    S.X.Ake = state16[11];
    S.X.Aki = state16[12];
    S.X.Ako = state16[13];
    S.X.Aku = state16[14];
    S.X.Ama = state16[15];
    S.X.Ame = state16[16];
    S.X.Ami = npub16[0];
    S.X.Amo = npub16[1];
    S.X.Amu = npub16[2];
    S.X.Asa = npub16[3];
    S.X.Ase = npub16[4];
    S.X.Asi = npub16[5];
    S.X.Aso = npub16[6];
    S.X.Asu = npub16[7];
    PermuteRoundsEX;

    // Squeeze key stream
    UINT64 rem_bytes = mlen;
    UINT64 idx = 0;
    while(1){
        if(rem_bytes>ISAP_rH_SZ){
            // Squeeze full lane and continue
            union Lane lane;
            lane.l64[0] = S.l64[0] ^ *((UINT64 *)(m+idx+0));
            lane.l64[1] = S.l64[1] ^ *((UINT64 *)(m+idx+8));
            lane.l16[8] = S.l16[8] ^ *((UINT16 *)(m+idx+16));
            memcpy(c+idx, &lane, ISAP_rH_SZ);
            idx += ISAP_rH_SZ;
            rem_bytes -= ISAP_rH_SZ;
            PermuteRoundsEX;
        } else if(rem_bytes==ISAP_rH_SZ){
            // Squeeze full lane and stop
            union Lane lane;
            lane.l64[0] = S.l64[0] ^ *((UINT64 *)(m+idx+0));
            lane.l64[1] = S.l64[1] ^ *((UINT64 *)(m+idx+8));
            lane.l16[8] = S.l16[8] ^ *((UINT16 *)(m+idx+16));
            memcpy(c+idx, &lane, ISAP_rH_SZ);
            break;
        } else {
            // Squeeze partial lane and stop
            for (size_t i = 0; i < rem_bytes; i++) {
                c[idx] = S.l8[i] ^ m[idx];
                idx++;
            }
            break;
        }
    }
}
