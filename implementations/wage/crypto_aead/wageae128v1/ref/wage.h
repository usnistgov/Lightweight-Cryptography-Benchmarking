
/* Reference implementation of the WAGE-128 permutation
 Written by:
 Kalikinkar Mandal <kmandal@uwaterloo.ca>
 */

#ifndef WAGE_H
#define WAGE_H

#include<math.h>
#include<stdlib.h>
#include<stdint.h>
#define mask	0x7f

#define STATEBYTES	37 //Number OF BYTES = \lceil 256/7 \rceil = 37
#define WAGEROUNDS	111 //Number of rounds

typedef unsigned long long u64;

void  wage_print_data(const unsigned char *x, const uint32_t xlen );

void wage_permutation( unsigned char *input );

void convert_8bytes_to_7bitwords (unsigned char *out, const unsigned char *in, u64 start_indx );

void convert_7bitwords_to_8bytes (unsigned char *out, const unsigned char *in, u64 start_indx );

void convert_bytekey_to_wordkey (unsigned char *out, const unsigned char *inp );

void convert_tag_word_to_byte (unsigned char *out, const unsigned char *inp );


void wage_print_state( const unsigned char *state );

void wage_permutation_ALLZERO ( unsigned char *state );

void wage_permutation_ALLONE ( unsigned char *state );

#endif
