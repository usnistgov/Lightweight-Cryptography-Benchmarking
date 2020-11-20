/*
Implementation by the Keccak Team, namely, Guido Bertoni, Joan Daemen,
Michaël Peeters, Gilles Van Assche and Ronny Van Keer,
hereby denoted as "the implementer".

For more information, feedback or questions, please refer to our website:
https://keccak.team/

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/

---

This file implements Keccak-p[1600] in a SnP-compatible way.
Please refer to SnP-documentation.h for more details.

This implementation comes with KeccakP-1600-SnP.h in the same folder.
Please refer to LowLevel.build for the exact list of other files it must be combined with.
*/

#include <string.h>
#include <stdlib.h>
#include "KeccakP-1600-opt64-config.h"
#include "elephant_200.h"

#if defined(KeccakP1600_useLaneComplementing)
#define UseBebigokimisa
#endif

/*
#if defined(_MSC_VER)
#define ROL64(a, offset) _rotl64(a, offset)
#elif defined(KeccakP1600_useSHLD)
    #define ROL64(x,N) ({ \
    register WORD __out; \
    register WORD __in = x; \
    __asm__ ("shld %2,%0,%0" : "=r"(__out) : "0"(__in), "i"(N)); \
    __out; \
    })
#else
#define ROL64(a, offset) ((((WORD)a) << offset) ^ (((WORD)a) >> (64-offset)))
#endif
*/

#include "KeccakP-1600-64.macros"
#ifdef KeccakP1600_fullUnrolling
#define FullUnrolling
#else
#define Unrolling KeccakP1600_unrolling
#endif
#include "KeccakP-1600-unrolling.macros"

/* ---------------------------------------------------------------- */

void KeccakP1600_Initialize(void *state)
{
    memset(state, 0, 200);
#ifdef KeccakP1600_useLaneComplementing
    ((WORD*)state)[ 1] = ~(WORD)0;
    ((WORD*)state)[ 2] = ~(WORD)0;
    ((WORD*)state)[ 8] = ~(WORD)0;
    ((WORD*)state)[12] = ~(WORD)0;
    ((WORD*)state)[17] = ~(WORD)0;
    ((WORD*)state)[20] = ~(WORD)0;
#endif
}

/* ---------------------------------------------------------------- */

void KeccakP1600_Permute_Nrounds(WORD* state, unsigned int nr)
{
    declareABCDE
    unsigned int i;

    copyFromState(A, state)
    roundsN(nr)
    copyToState(state, A)
}

/* ---------------------------------------------------------------- */

void KeccakP1600_Permute_18rounds(WORD* state)
{
    declareABCDE
    #ifndef KeccakP1600_fullUnrolling
    unsigned int i;
    #endif

    copyFromState(A, state)
    rounds18
    copyToState(state, A)
}

void bigpermutation(WORD* big_state)
{
    KeccakP1600_Permute_18rounds(big_state);
}
#define nrLanes 25
void permutation(BYTE* state)
{
    WORD big_state[nrLanes];
    for(SIZE i = 0; i < nrLanes; i++)
      big_state[i] = slice_in((WORD)state[i]);

    KeccakP1600_Permute_18rounds(big_state);

    for(SIZE i = 0; i < nrLanes; i++)
      state[i] = slice_in(big_state[i]);
}
