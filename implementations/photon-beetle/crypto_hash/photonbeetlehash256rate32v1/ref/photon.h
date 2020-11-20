#ifndef __PHOTON_H_
#define __PHOTON_H_

#include <stdint.h>

#define ROUND			12
#define min(x,y) ((x)<(y)?(x):(y))
#define max(x,y) ((x)>(y)?(x):(y))

#define D				8


typedef uint8_t	byte;
typedef uint32_t	u32;
typedef uint64_t	u64;
typedef uint32_t CWord;
typedef u32 tword;

typedef struct{
	u64 h;
	u64 l;
}u128; // state word


#ifdef _TABLE_
void BuildTableSCShRMCS();
#endif

void PrintState(byte state[D][D]);

void PHOTON_Permutation(unsigned char *State_inout);

#endif /*  end of photon.h */
