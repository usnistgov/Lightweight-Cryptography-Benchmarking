/*
Implementation by the Keccak Team, namely, Guido Bertoni, Joan Daemen,
Michaël Peeters, Gilles Van Assche and Ronny Van Keer,
hereby denoted as "the implementer".

For more information, feedback or questions, please refer to our website:
https://keccak.team/

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/
*/

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "brg_endian.h"

typedef unsigned char UINT8;
typedef unsigned short UINT16;
typedef UINT16 tKeccakLane;

#define maxNrRounds 20
#define nrLanes 25
#define index(x, y) (((x)%5)+5*((y)%5))

/* ---------------------------------------------------------------- */

static const tKeccakLane KeccakRoundConstants[maxNrRounds] =
{
    0x0001,
    0x8082,
    0x808a,
    0x8000,
    0x808b,
    0x0001,
    0x8081,
    0x8009,
    0x008a,
    0x0088,
    0x8009,
    0x000a,
    0x808b,
    0x008b,
    0x8089,
    0x8003,
    0x8002,
    0x0080,
    0x800a,
    0x000a,
};

/* ---------------------------------------------------------------- */

static const unsigned int KeccakRhoOffsets[nrLanes] =
{
     0,  1, 14, 12, 11,  4, 12,  6,  7,  4,  3, 10, 11,  9,  7,  9, 13, 15,  5,  8,  2,  2, 13,  8, 14
};

/* ---------------------------------------------------------------- */

void KeccakP400_Initialize(void *state)
{
    memset(state, 0, nrLanes * sizeof(tKeccakLane));
}

/* ---------------------------------------------------------------- */

void KeccakP400_AddByte(void *state, unsigned char byte, unsigned int offset)
{
    assert(offset < 50);
    ((unsigned char *)state)[offset] ^= byte;
}

/* ---------------------------------------------------------------- */

void KeccakP400_AddBytes(void *state, const unsigned char *data, unsigned int offset, unsigned int length)
{
    unsigned int i;

    assert(offset < 50);
    assert(offset+length <= 50);
    for(i=0; i<length; i++)
        ((unsigned char *)state)[offset+i] ^= data[i];
}

/* ---------------------------------------------------------------- */

void KeccakP400_OverwriteBytes(void *state, const unsigned char *data, unsigned int offset, unsigned int length)
{
    assert(offset < 50);
    assert(offset+length <= 50);
    memcpy((unsigned char*)state+offset, data, length);
}

/* ---------------------------------------------------------------- */

void KeccakP400_OverwriteWithZeroes(void *state, unsigned int byteCount)
{
    assert(byteCount <= 50);
    memset(state, 0, byteCount);
}

/* ---------------------------------------------------------------- */

void KeccakP400OnWords(tKeccakLane *state, unsigned int nrRounds);
void KeccakP400Round(tKeccakLane *state, unsigned int indexRound);
static void theta(tKeccakLane *A);
static void rho(tKeccakLane *A);
static void pi(tKeccakLane *A);
static void chi(tKeccakLane *A);
static void iota(tKeccakLane *A, unsigned int indexRound);

void KeccakP400_Permute_Nrounds(void *state, unsigned int nrounds)
{
#if (PLATFORM_BYTE_ORDER != IS_LITTLE_ENDIAN)
    tKeccakLane stateAsWords[nrLanes];
#endif

#if (PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN)
    KeccakP400OnWords((tKeccakLane*)state, nrounds);
#else
    fromBytesToWords(stateAsWords, (const unsigned char *)state);
    KeccakP400OnWords(stateAsWords, nrounds);
    fromWordsToBytes((unsigned char *)state, stateAsWords);
#endif
}

void KeccakP400_Permute_20rounds(void *state)
{
#if (PLATFORM_BYTE_ORDER != IS_LITTLE_ENDIAN)
    tKeccakLane stateAsWords[nrLanes];
#endif

#if (PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN)
    KeccakP400OnWords((tKeccakLane*)state, maxNrRounds);
#else
    fromBytesToWords(stateAsWords, (const unsigned char *)state);
    KeccakP400OnWords(stateAsWords, maxNrRounds);
    fromWordsToBytes((unsigned char *)state, stateAsWords);
#endif
}

void KeccakP400OnWords(tKeccakLane *state, unsigned int nrRounds)
{
    unsigned int i;
    for(i=(maxNrRounds-nrRounds); i<maxNrRounds; i++)
        KeccakP400Round(state, i);
}

void KeccakP400Round(tKeccakLane *state, unsigned int indexRound)
{
    theta(state);
    rho(state);
    pi(state);
    chi(state);
    iota(state, indexRound);
}

#define ROL16(a, offset) ((offset != 0) ? ((((tKeccakLane)a) << offset) ^ (((tKeccakLane)a) >> (sizeof(tKeccakLane)*8-offset))) : a)

static void theta(tKeccakLane *A)
{
    unsigned int x, y;
    tKeccakLane C[5], D[5];

    for(x=0; x<5; x++) {
        C[x] = 0;
        for(y=0; y<5; y++)
            C[x] ^= A[index(x, y)];
    }
    for(x=0; x<5; x++)
        D[x] = ROL16(C[(x+1)%5], 1) ^ C[(x+4)%5];
    for(x=0; x<5; x++)
        for(y=0; y<5; y++)
            A[index(x, y)] ^= D[x];
}

static void rho(tKeccakLane *A)
{
    unsigned int x, y;

    for(x=0; x<5; x++) for(y=0; y<5; y++)
        A[index(x, y)] = ROL16(A[index(x, y)], KeccakRhoOffsets[index(x, y)]);
}

static void pi(tKeccakLane *A)
{
    unsigned int x, y;
    tKeccakLane tempA[25];

    for(x=0; x<5; x++) for(y=0; y<5; y++)
        tempA[index(x, y)] = A[index(x, y)];
    for(x=0; x<5; x++) for(y=0; y<5; y++)
        A[index(0*x+1*y, 2*x+3*y)] = tempA[index(x, y)];
}

static void chi(tKeccakLane *A)
{
    unsigned int x, y;
    tKeccakLane C[5];

    for(y=0; y<5; y++) {
        for(x=0; x<5; x++)
            C[x] = A[index(x, y)] ^ ((~A[index(x+1, y)]) & A[index(x+2, y)]);
        for(x=0; x<5; x++)
            A[index(x, y)] = C[x];
    }
}

static void iota(tKeccakLane *A, unsigned int indexRound)
{
    A[index(0, 0)] ^= KeccakRoundConstants[indexRound];
}

/* ---------------------------------------------------------------- */

void KeccakP400_ExtractBytes(const void *state, unsigned char *data, unsigned int offset, unsigned int length)
{
    assert(offset < 50);
    assert(offset+length <= 50);
    memcpy(data, (unsigned char*)state+offset, length);
}

/* ---------------------------------------------------------------- */

void KeccakP400_ExtractAndAddBytes(const void *state, const unsigned char *input, unsigned char *output, unsigned int offset, unsigned int length)
{
    unsigned int i;

    assert(offset < 50);
    assert(offset+length <= 50);
    for(i=0; i<length; i++)
        output[i] = input[i] ^ ((unsigned char *)state)[offset+i];
}
