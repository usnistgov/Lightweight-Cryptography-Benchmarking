/**
 * Based on the implementation by the Keccak Team, namely, Guido Bertoni, Joan Daemen,
 * Michaël Peeters, Gilles Van Assche and Ronny Van Keer.
 */
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "elephant_200.h"

#define maxNrRounds 18
#define nrLanes 25
#define index(x, y) (((x)%5)+5*((y)%5))

const BYTE KeccakRoundConstants[maxNrRounds] = {
    0x01, 0x82, 0x8a, 0x00, 0x8b, 0x01, 0x81, 0x09, 0x8a,
    0x88, 0x09, 0x0a, 0x8b, 0x8b, 0x89, 0x03, 0x02, 0x80
};

const unsigned int KeccakRhoOffsets[nrLanes] = {
    0, 1, 6, 4, 3, 4, 4, 6, 7, 4, 3, 2, 3, 1, 7, 1, 5, 7, 5, 0, 2, 2, 5, 0, 6
};

#define ROL8(a, offset) ((offset != 0) ? ((((BYTE)a) << offset) ^ (((BYTE)a) >> (sizeof(BYTE)*8-offset))) : a)

void theta(BYTE *A)
{
    unsigned int x, y;
    BYTE C[5], D[5];

    for(x=0; x<5; x++) {
        C[x] = 0;
        for(y=0; y<5; y++)
            C[x] ^= A[index(x, y)];
    }
    for(x=0; x<5; x++)
        D[x] = ROL8(C[(x+1)%5], 1) ^ C[(x+4)%5];
    for(x=0; x<5; x++)
        for(y=0; y<5; y++)
            A[index(x, y)] ^= D[x];
}

void rho(BYTE *A)
{
    for(unsigned int x=0; x<5; x++)
        for(unsigned int y=0; y<5; y++)
            A[index(x, y)] = ROL8(A[index(x, y)], KeccakRhoOffsets[index(x, y)]);
}

void pi(BYTE *A)
{
    BYTE tempA[25];

    for(unsigned int x=0; x<5; x++)
        for(unsigned int y=0; y<5; y++)
            tempA[index(x, y)] = A[index(x, y)];
    for(unsigned int x=0; x<5; x++)
        for(unsigned int y=0; y<5; y++)
            A[index(0*x+1*y, 2*x+3*y)] = tempA[index(x, y)];
}

void chi(BYTE *A)
{
    unsigned int x, y;
    BYTE C[5];

    for(y=0; y<5; y++) {
        for(x=0; x<5; x++)
            C[x] = A[index(x, y)] ^ ((~A[index(x+1, y)]) & A[index(x+2, y)]);
        for(x=0; x<5; x++)
            A[index(x, y)] = C[x];
    }
}

void iota(BYTE *A, unsigned int indexRound)
{
    A[index(0, 0)] ^= KeccakRoundConstants[indexRound];
}

void KeccakP200Round(BYTE *state, unsigned int indexRound)
{
    theta(state);
    rho(state);
    pi(state);
    chi(state);
    iota(state, indexRound);
}

void permutation(BYTE* state)
{
    for(unsigned int i=0; i<maxNrRounds; i++)
        KeccakP200Round(state, i);
}
