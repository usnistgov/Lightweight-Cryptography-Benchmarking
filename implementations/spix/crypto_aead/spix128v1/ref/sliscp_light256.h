
/* Reference implementation of SPIX-128 AEAD
   Written by:
   Kalikinkar Mandal <kmandal@uwaterloo.ca>
*/

#ifndef SLISCP_LIGHT256_H
#define SLISCP_LIGHT256_H

#include<math.h>
#include<stdlib.h>
#include<stdint.h>


#define STATEBYTES		32 //NUM OF WORDS = 256/8 = 32
#define SIMECKBYTES		8 // number of words = 64/8 = 8
#define SIMECKROUND    		8
#define NUMSTEPSR9		9
#define NUMSTEPSR18             18

typedef unsigned long long u64;

uint8_t rotl8 ( const uint8_t x, const uint8_t y, const uint8_t shift );

void  sliscp_print_data(const uint8_t *x, const uint32_t xlen );

void  simeck_print_data(const uint8_t *y, const uint8_t ylen );

void simeck64_box( uint8_t *output, const uint8_t *input, const uint8_t rc );

void sliscp_permutation256r9 ( uint8_t *input );

void sliscp_permutation256r18 ( uint8_t *input );

void sliscp_print_state256 ( const uint8_t *state );

void sliscp_permutation256_ALLZERO ( uint8_t *state );

void sliscp_permutation256_ALLONE ( uint8_t *state );

#endif
