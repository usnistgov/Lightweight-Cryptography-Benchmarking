#include <stdio.h>
#include "isap.h"
#include "KeccakP-400-SnP.h"

void Permutation_Initialize(
	void *state
){
	KeccakP400_Initialize(state);
}

void Permutation_AddBytes(
	void *state,
	const unsigned char *data,
	unsigned int offset,
	unsigned int length
){
	KeccakP400_AddBytes(state,data,offset,length);
}

void Permutation_OverwriteBytes(
	void *state,
	const unsigned char *data,
	unsigned int offset,
	unsigned int length
){
	KeccakP400_OverwriteBytes(state,data,offset,length);
}

void Permutation_Permute_Nrounds(
	void *state,
	unsigned int nrounds
){
	KeccakP400_Permute_Nrounds(state,nrounds);
}

void Permutation_ExtractBytes(
	const void *state,
	unsigned char *data,
	unsigned int offset,
	unsigned int length
){
	KeccakP400_ExtractBytes(state,data,offset,length);
}

