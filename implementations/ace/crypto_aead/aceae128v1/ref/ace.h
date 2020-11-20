
/* Reference implementation of the ACE permutation
 Written by:
 Kalikinkar Mandal <kmandal@uwaterloo.ca>
 */

#ifndef ACE_H
#define ACE_H

#include<math.h>
#include<stdlib.h>
#include<stdint.h>


#define STATEBYTES		40 //Number OF BYTES = 320/8 = 40
#define SIMECKBYTES		8 //Number of Simeck BYTES = 64/8 = 8
#define SIMECKROUND    		8 //Number of rounds
#define NUMSTEPS		16 //Number of steps


typedef unsigned long long u64;

unsigned char rotl8 ( const unsigned char x, const unsigned char y, const unsigned char shift );

void  ace_print_data(const unsigned char *x, const uint32_t xlen );

void  simeck_print_data(const unsigned char *y, const unsigned char ylen );

void simeck64_box( unsigned char *output, const unsigned char *input, const unsigned char rc );

void ace_permutation( unsigned char *input );

void ace_print_state( const unsigned char *state );

void ace_permutation_ALLZERO ( unsigned char *state );

void ace_permutation_ALLONE ( unsigned char *state );

#endif
