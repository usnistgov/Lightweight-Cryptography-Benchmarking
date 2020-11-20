/* Reference implementation of the sliscp_light192 permutation.
   Written by:
   Kalikinkar Mandal <kmandal@uwaterloo.ca>
*/
#ifndef SLISCP_LIGHT192_H
#define SLISCP_LIGHT192_H

#include<math.h>
#include<stdlib.h>
#include<stdint.h>


#define STATEBYTES		24 //NUM OF WORDS = 192/8 = 24
#define SIMECKBYTES		6 // number of words = 48/8 = 6
#define SIMECKROUND    		6
#define NUMSTEPSFULL            18

typedef unsigned long long u64;

uint8_t rotl8 ( const uint8_t x, const uint8_t y, const uint8_t shift );

void  sliscp_print_data(const uint8_t *x, const uint32_t xlen );

void  simeck_print_data(const uint8_t *y, const uint8_t ylen );

void simeck48_box( uint8_t *output, const uint8_t *input, const uint8_t rc );

void sliscp_permutation192r18 ( uint8_t *input );

void sliscp_print_state192 ( const uint8_t *state );

void sliscp_permutation192r18_ALLZERO ( uint8_t *state );

void sliscp_permutation192r18_ALLONE ( uint8_t *state );

#endif
