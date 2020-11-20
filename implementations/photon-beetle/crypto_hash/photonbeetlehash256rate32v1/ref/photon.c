#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include "photon.h"

#define S				4
const byte ReductionPoly = 0x3;
const byte WORDFILTER = ((byte) 1<<S)-1;
int DEBUG = 0;

/* to be completed for one time pass mode */
unsigned long long MessBitLen = 0;

const byte RC[D][12] = {
	{1, 3, 7, 14, 13, 11, 6, 12, 9, 2, 5, 10},
	{0, 2, 6, 15, 12, 10, 7, 13, 8, 3, 4, 11},
	{2, 0, 4, 13, 14, 8, 5, 15, 10, 1, 6, 9},
	{6, 4, 0, 9, 10, 12, 1, 11, 14, 5, 2, 13},
	{14, 12, 8, 1, 2, 4, 9, 3, 6, 13, 10, 5},
	{15, 13, 9, 0, 3, 5, 8, 2, 7, 12, 11, 4},
	{13, 15, 11, 2, 1, 7, 10, 0, 5, 14, 9, 6},
	{9, 11, 15, 6, 5, 3, 14, 4, 1, 10, 13, 2}
};

const byte MixColMatrix[D][D] = {
	{ 2,  4,  2, 11,  2,  8,  5,  6},
	{12,  9,  8, 13,  7,  7,  5,  2},
	{ 4,  4, 13, 13,  9,  4, 13,  9},
	{ 1,  6,  5,  1, 12, 13, 15, 14},
	{15, 12,  9, 13, 14,  5, 14, 13},
	{ 9, 14,  5, 15,  4, 12,  9,  6},
	{12,  2,  2, 10,  3,  1,  1, 14},
	{15,  1, 13, 10,  5, 10,  2,  3}
};

byte sbox[16] = {12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2};

byte FieldMult(byte a, byte b)
{
	byte x = a, ret = 0;
	int i;
	for(i = 0; i < S; i++) {
		if((b>>i)&1) ret ^= x;
		if((x>>(S-1))&1) {
			x <<= 1;
			x ^= ReductionPoly;
		}
		else x <<= 1;
	}
	return ret&WORDFILTER;
}

void PrintState(byte state[D][D])
{
	if(!DEBUG) return;
	int i, j;
	for(i = 0; i < D; i++){
		for(j = 0; j < D; j++)
			printf("%2X ", state[i][j]);
		printf("\n");
	}
	printf("\n");
}

void PrintState_Column(CWord state[D])
{
	if(!DEBUG) return;
	int i, j;
	for(i = 0; i < D; i++){
		for(j = 0; j < D; j++)
			printf("%2X ", (state[j]>>(i*S)) & WORDFILTER);
		printf("\n");
	}
	printf("\n");
}

void AddKey(byte state[D][D], int round)
{
	int i;
	for(i = 0; i < D; i++)
		state[i][0] ^= RC[i][round];
}

void SubCell(byte state[D][D])
{
	int i,j;
	for(i = 0; i < D; i++)
		for(j = 0; j <  D; j++)
			state[i][j] = sbox[state[i][j]];
}

void ShiftRow(byte state[D][D])
{
	int i, j;
	byte tmp[D];
	for(i = 1; i < D; i++) {
		for(j = 0; j < D; j++)
			tmp[j] = state[i][j];
		for(j = 0; j < D; j++)
			state[i][j] = tmp[(j+i)%D];
	}
}

void MixColumn(byte state[D][D])
{
	int i, j, k;
	byte tmp[D];
	for(j = 0; j < D; j++){
		for(i = 0; i < D; i++) {
			byte sum = 0;
			for(k = 0; k < D; k++)
				sum ^= FieldMult(MixColMatrix[i][k], state[k][j]);
			tmp[i] = sum;
		}
		for(i = 0; i < D; i++)
			state[i][j] = tmp[i];
	}
}


#ifdef _TABLE_
tword Table[D][1<<S];
void BuildTableSCShRMCS()
{
	int c, v, r;
	tword tv;
	for(v = 0; v < (1<<S); v++) {
		for(c = 0; c < D; c++){ // compute the entry Table[c][v]
			tv = 0;
			for(r = 0; r < D; r++){
				tv <<= S;
				tv |= (tword) FieldMult(MixColMatrix[r][c], sbox[v]);
			}
			Table[c][v] = tv;
		}
	}
	if(DEBUG){
		printf("tword Table[D][1<<S] = {\n");
		for(c = 0; c < D; c++){ 
			printf("\t{");
			for(v = 0; v < (1<<S); v++) {
				printf("0x%.8XU, ", Table[c][v]);
			}
			printf("}");
			if(v != (1<<S)-1) printf(",");
			printf("\n");
		}
		printf("};\n");
	}
}

void SCShRMCS(byte state[D][D])
{
	int c,r;
	tword v;
	byte os[D][D];
	memcpy(os, state, D*D);

	for(c = 0; c < D; c++){ // for all columns
		v = 0;
		for(r = 0; r < D; r++) // for all rows in this column i after ShiftRow
			v ^= Table[r][os[r][(r+c)%D]];

		for(r = 1; r <= D; r++){
			state[D-r][c] = (byte)v & WORDFILTER;
			v >>= S;
		}
	}
}
#endif

void Permutation(byte state[D][D], int R)
{
	int i;
	for(i = 0; i < R; i++) {
		if(DEBUG) printf("--- Round %d ---\n", i);
		AddKey(state, i); PrintState(state);
#ifndef _TABLE_
		SubCell(state); PrintState(state);
		ShiftRow(state); PrintState(state);
		MixColumn(state); 
#else
		SCShRMCS(state);
#endif
		PrintState(state);
	}
}

void PHOTON_Permutation(unsigned char *State_in)
{
    byte state[D][D];
    int i;

	for (i = 0; i < D * D; i++)
	{
		state[i / D][i % D] = (State_in[i / 2] >> (4 * (i & 1))) & 0xf;
	}
   
    Permutation(state, ROUND);

	memset(State_in, 0, (D * D) / 2);
	for (i = 0; i < D * D; i++)
	{
		State_in[i / 2] |= (state[i / D][i % D] & 0xf) << (4 * (i & 1));
	}
}