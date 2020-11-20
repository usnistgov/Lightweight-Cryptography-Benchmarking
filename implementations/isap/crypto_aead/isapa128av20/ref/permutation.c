#include <stdio.h>
#include "isap.h"
#include "Ascon-reference.h"

void Permutation_Initialize(
	void *state
){
	Ascon_Initialize(state);
}

void Permutation_AddBytes(
	void *state,
	const unsigned char *data,
	unsigned int offset,
	unsigned int length
){
	Ascon_AddBytes(state,data,offset,length);
}

void Permutation_OverwriteBytes(
	void *state,
	const unsigned char *data,
	unsigned int offset,
	unsigned int length
){
	Ascon_OverwriteBytes(state,data,offset,length);
}

void Permutation_Permute_Nrounds(
	void *state,
	unsigned int nrounds
){
	Ascon_Permute_Nrounds(state,nrounds);
}

void Permutation_ExtractBytes(
	const void *state,
	unsigned char *data,
	unsigned int offset,
	unsigned int length
){
	Ascon_ExtractBytes(state,data,offset,length);
}

