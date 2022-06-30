#ifndef ELEPHANT_176
#define ELEPHANT_176

#define SPONGENT176
#define BLOCK_SIZE 22

typedef unsigned char BYTE;
typedef unsigned long long SIZE;

void permutation(BYTE* state);

void lfsr_step(BYTE* output, BYTE* input);

void get_ad_block(BYTE* output, const BYTE* ad, SIZE adlen, const BYTE* npub, SIZE i);

void get_c_block(BYTE* output, const BYTE* c, SIZE clen, SIZE i);


#endif
