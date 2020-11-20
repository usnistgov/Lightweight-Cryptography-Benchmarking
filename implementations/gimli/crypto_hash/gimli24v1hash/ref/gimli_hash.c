#include <stdint.h>
#include <string.h>
#include "crypto_hash.h"

#include "gimli.inc"

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define rateInBytes 16

static void Gimli_hash(const uint8_t *input,
                uint64_t inputByteLen,
                uint8_t *output,
                uint64_t outputByteLen)
{
    uint8_t state_8[48];
    uint64_t blockSize = 0;
    uint64_t i;

    // === Initialize the state ===
    memset(state_8, 0, sizeof(state_8));

    // === Absorb all the input blocks ===
    while(inputByteLen > 0) {
        blockSize = MIN(inputByteLen, rateInBytes);
        for(i=0; i<blockSize; i++)
            state_8[i] ^= input[i];
        input += blockSize;
        inputByteLen -= blockSize;

        if (blockSize == rateInBytes) {
            gimli(state_8);
            blockSize = 0;
        }
    }

    // === Do the padding and switch to the squeezing phase ===
    state_8[blockSize] ^= 1;
    // Fork
    state_8[48-1] ^= 1;
    // Switch to the squeezing phase
    gimli(state_8);

    // === Squeeze out all the output blocks ===
    while(outputByteLen > 0) {
        blockSize = MIN(outputByteLen, rateInBytes);
        memcpy(output, state_8, blockSize);
        output += blockSize;
        outputByteLen -= blockSize;

        if (outputByteLen > 0)
            gimli(state_8);
    }
}

int crypto_hash(unsigned char *out,const unsigned char *in,unsigned long long inlen)
{
  Gimli_hash(in,inlen,out,32);
  return 0;
}
