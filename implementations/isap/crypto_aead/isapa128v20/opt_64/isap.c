#include <stdio.h>
#include <string.h>
#include "api.h"
#include "isap.h"

typedef unsigned char u8;
typedef unsigned long long u64;
typedef unsigned long u32;
typedef long long i64;

const u8 ISAP_IV1[] = {0x01,ISAP_K,ISAP_rH,ISAP_rB,ISAP_sH,ISAP_sB,ISAP_sE,ISAP_sK};
const u8 ISAP_IV2[] = {0x02,ISAP_K,ISAP_rH,ISAP_rB,ISAP_sH,ISAP_sB,ISAP_sE,ISAP_sK};
const u8 ISAP_IV3[] = {0x03,ISAP_K,ISAP_rH,ISAP_rB,ISAP_sH,ISAP_sB,ISAP_sE,ISAP_sK};

#define RATE (64 / 8)
#define PA_ROUNDS 12
#define PB_ROUNDS 6

#define ROTR(x,n) (((x)>>(n))|((x)<<(64-(n))))
#define EXT_BYTE(x,n) ((u8)((u64)(x)>>(8*(7-(n)))))
#define INS_BYTE(x,n) ((u64)(x)<<(8*(7-(n))))

#define U64BIG(x) \
    ((ROTR(x, 8) & (0xFF000000FF000000ULL)) | \
     (ROTR(x,24) & (0x00FF000000FF0000ULL)) | \
     (ROTR(x,40) & (0x0000FF000000FF00ULL)) | \
     (ROTR(x,56) & (0x000000FF000000FFULL)))

#define ROUND(C) ({\
    x2 ^= C;\
    x0 ^= x4;\
    x4 ^= x3;\
    x2 ^= x1;\
    t0 = x0;\
    t4 = x4;\
    t3 = x3;\
    t1 = x1;\
    t2 = x2;\
    x0 = t0 ^ ((~t1) & t2);\
    x2 = t2 ^ ((~t3) & t4);\
    x4 = t4 ^ ((~t0) & t1);\
    x1 = t1 ^ ((~t2) & t3);\
    x3 = t3 ^ ((~t4) & t0);\
    x1 ^= x0;\
    t1  = x1;\
    x1 = ROTR(x1, R[1][0]);\
    x3 ^= x2;\
    t2  = x2;\
    x2 = ROTR(x2, R[2][0]);\
    t4  = x4;\
    t2 ^= x2;\
    x2 = ROTR(x2, R[2][1] - R[2][0]);\
    t3  = x3;\
    t1 ^= x1;\
    x3 = ROTR(x3, R[3][0]);\
    x0 ^= x4;\
    x4 = ROTR(x4, R[4][0]);\
    t3 ^= x3;\
    x2 ^= t2;\
    x1 = ROTR(x1, R[1][1] - R[1][0]);\
    t0  = x0;\
    x2 = ~x2;\
    x3 = ROTR(x3, R[3][1] - R[3][0]);\
    t4 ^= x4;\
    x4 = ROTR(x4, R[4][1] - R[4][0]);\
    x3 ^= t3;\
    x1 ^= t1;\
    x0 = ROTR(x0, R[0][0]);\
    x4 ^= t4;\
    t0 ^= x0;\
    x0 = ROTR(x0, R[0][1] - R[0][0]);\
    x0 ^= t0;\
})

#define P12 ({\
    ROUND(0xf0);\
    ROUND(0xe1);\
    ROUND(0xd2);\
    ROUND(0xc3);\
    ROUND(0xb4);\
    ROUND(0xa5);\
    ROUND(0x96);\
    ROUND(0x87);\
    ROUND(0x78);\
    ROUND(0x69);\
    ROUND(0x5a);\
    ROUND(0x4b);\
})

#define P6 ({\
    ROUND(0x96);\
    ROUND(0x87);\
    ROUND(0x78);\
    ROUND(0x69);\
    ROUND(0x5a);\
    ROUND(0x4b);\
})

#define P1 ({\
    ROUND(0x4b);\
})

static const int R[5][2] = {
    {19, 28}, {39, 61}, {1, 6}, {10, 17}, {7, 41}
};

#define ABSORB_MAC(src, len) ({ \
    u32 rem_bytes = len; \
    u64 *src64 = (u64 *)src; \
    u32 idx64 = 0; \
    while(1){ \
        if(rem_bytes>ISAP_rH_SZ){ \
            x0 ^= U64BIG(src64[idx64]); \
            idx64++; \
            P12; \
            rem_bytes -= ISAP_rH_SZ; \
        } else if(rem_bytes==ISAP_rH_SZ){ \
            x0 ^= U64BIG(src64[idx64]); \
            P12; \
            x0 ^= 0x8000000000000000ULL; \
            P12; \
            break; \
        } else { \
            u64 lane64; \
            u8 *lane8 = (u8 *)&lane64; \
            u32 idx8 = idx64*8; \
            for (u32 i = 0; i < 8; i++) { \
                if(i<(rem_bytes)){ \
                    lane8[i] = src[idx8]; \
                    idx8++; \
                } else if(i==rem_bytes){ \
                    lane8[i] = 0x80; \
                } else { \
                    lane8[i] = 0x00; \
                } \
            } \
            x0 ^= U64BIG(lane64); \
            P12; \
            break; \
        } \
    } \
})

/******************************************************************************/
/*                                   IsapRk                                   */
/******************************************************************************/

void isap_rk(
	const u8 *k,
	const u8 *iv,
	const u8 *y,
	const u64 ylen,
	u8 *out,
	const u64 outlen
){
    const u64 *k64 = (u64 *)k;
    const u64 *iv64 = (u64 *)iv;
    u64 *out64 = (u64 *)out;
    u64 x0, x1, x2, x3, x4;
    u64 t0, t1, t2, t3, t4;

    // Init state
    t0 = t1 = t2 = t3 = t4 = 0;
    x0 = U64BIG(k64[0]);
    x1 = U64BIG(k64[1]);
    x2 = U64BIG(iv64[0]);
    x3 = x4 = 0;
    P12;

    // Absorb Y
    for (size_t i = 0; i < ylen*8-1; i++){
        size_t cur_byte_pos = i/8;
        size_t cur_bit_pos = 7-(i%8);
        u8 cur_bit = ((y[cur_byte_pos] >> (cur_bit_pos)) & 0x01) << 7;
        x0 ^= ((u64)cur_bit) << 56;
        P12;
    }
    u8 cur_bit = ((y[ylen-1]) & 0x01) << 7;
    x0 ^= ((u64)cur_bit) << 56;
    P12;

    // Extract K*
    out64[0] = U64BIG(x0);
    out64[1] = U64BIG(x1);
    if(outlen == 24){
        out64[2] = U64BIG(x2);
    }
}

/******************************************************************************/
/*                                  IsapMac                                   */
/******************************************************************************/

void isap_mac(
    const u8 *k,
    const u8 *npub,
    const u8 *ad, const u64 adlen,
    const u8 *c, const u64 clen,
    u8 *tag
){
    u8 state[ISAP_STATE_SZ];
    const u64 *npub64 = (u64 *)npub;
    u64 *state64 = (u64 *)state;
    u64 x0, x1, x2, x3, x4;
    u64 t0, t1, t2, t3, t4;
    t0 = t1 = t2 = t3 = t4 = 0;

    // Init state
    x0 = U64BIG(npub64[0]);
    x1 = U64BIG(npub64[1]);
    x2 = U64BIG(((u64 *)ISAP_IV1)[0]);
    x3 = x4 = 0;
    P12;

    // Absorb AD
    ABSORB_MAC(ad,adlen);

    // Domain seperation
    x4 ^= 0x0000000000000001ULL;

    // Absorb C
    ABSORB_MAC(c,clen);

    // Derive K*
    state64[0] = U64BIG(x0);
    state64[1] = U64BIG(x1);
    state64[2] = U64BIG(x2);
    state64[3] = U64BIG(x3);
    state64[4] = U64BIG(x4);
    isap_rk(k,ISAP_IV2,(u8 *)state64,CRYPTO_KEYBYTES,(u8 *)state64,CRYPTO_KEYBYTES);
    x0 = U64BIG(state64[0]);
    x1 = U64BIG(state64[1]);
    x2 = U64BIG(state64[2]);
    x3 = U64BIG(state64[3]);
    x4 = U64BIG(state64[4]);

    // Squeeze tag
    P12;
    unsigned long long *tag64 = (u64 *)tag;
    tag64[0] = U64BIG(x0);
    tag64[1] = U64BIG(x1);
}

/******************************************************************************/
/*                                  IsapEnc                                   */
/******************************************************************************/

void isap_enc(
	const u8 *k,
	const u8 *npub,
	const u8 *m,
    const u64 mlen,
	u8 *c
){
    u8 state[ISAP_STATE_SZ];

    // Init state
    u64 *state64 = (u64 *)state;
    u64 *npub64 = (u64 *)npub;
    isap_rk(k,ISAP_IV3,npub,CRYPTO_NPUBBYTES,state,ISAP_STATE_SZ-CRYPTO_NPUBBYTES);
    u64 x0, x1, x2, x3, x4;
    u64 t0, t1, t2, t3, t4;
    t0 = t1 = t2 = t3 = t4 = 0;
    x0 = U64BIG(state64[0]);
    x1 = U64BIG(state64[1]);
    x2 = U64BIG(state64[2]);
    x3 = U64BIG(npub64[0]);
    x4 = U64BIG(npub64[1]);
    P12;

    // Squeeze key stream
    u64 rem_bytes = mlen;
    u64 *m64 = (u64 *)m;
    u64 *c64 = (u64 *)c;
    u32 idx64 = 0;
    while(1){
        if(rem_bytes>ISAP_rH_SZ){
            // Squeeze full lane
            c64[idx64] = U64BIG(x0) ^ m64[idx64];
            idx64++;
            P12;
            rem_bytes -= ISAP_rH_SZ;
        } else if(rem_bytes==ISAP_rH_SZ){
            // Squeeze full lane and stop
            c64[idx64] = U64BIG(x0) ^ m64[idx64];
            break;
        } else {
            // Squeeze partial lane and stop
            u64 lane64 = U64BIG(x0);
            u8 *lane8 = (u8 *)&lane64;
            u32 idx8 = idx64*8;
            for (u32 i = 0; i < rem_bytes; i++) {
                c[idx8] = lane8[i] ^ m[idx8];
                idx8++;
            }
            break;
        }
    }
}
