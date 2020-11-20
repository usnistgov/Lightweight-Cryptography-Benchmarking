#ifndef ELEPHANT_200
#define ELEPHANT_200

#define BLOCK_SIZE 25
#define WORDSIZE 8

typedef unsigned char BYTE;
typedef unsigned long long SIZE;
typedef unsigned long long WORD;

#define ROL8(a, offset) (((((BYTE)a) << offset) ^ (((BYTE)a) >> (sizeof(BYTE)*8-offset))))
#define ROL64(a, offset) ((((WORD)a) << offset) ^ (((WORD)a) >> (64-offset)))

WORD slice_in(const WORD source);

void slice_in_all(WORD *source, SIZE size);

void permutation(BYTE* state);

void bigpermutation(WORD* state);

void lfsr_step(BYTE* output, BYTE* input);

void get_ad_block(BYTE* output, const BYTE* ad, SIZE adlen, const BYTE* npub, SIZE i);

void get_c_block(BYTE* output, const BYTE* c, SIZE clen, SIZE i);

#endif
