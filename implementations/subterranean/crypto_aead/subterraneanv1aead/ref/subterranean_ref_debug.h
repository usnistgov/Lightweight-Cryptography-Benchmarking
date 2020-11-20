#include <stdio.h>

#define DEBUG_MSG_MAX_SIZE 500

char debug_msg[DEBUG_MSG_MAX_SIZE];

void bits_to_hex_string(char * hex_string, const unsigned char * in_bits, const unsigned int in_len){
    unsigned int i, j;
    unsigned char temp, mult_factor;
    j = 0;
    for (i = 0; ((i < in_len-8) && (j < DEBUG_MSG_MAX_SIZE)); i+=8){
        temp = in_bits[i] + in_bits[i+1]*2 + in_bits[i+2]*4 + in_bits[i+3]*8 + in_bits[i+4]*16 + in_bits[i+5]*32 + in_bits[i+6]*64 + in_bits[i+7]*128;
        sprintf(&hex_string[j], "%02x",temp);
        j+=2;
    }
    temp = 0;
    mult_factor = 1;
    for (; i < in_len; i++){
        temp += mult_factor*in_bits[i];
        mult_factor *= 2;
    }
    if(j < DEBUG_MSG_MAX_SIZE-3){
        sprintf(&hex_string[j], "%02x",temp);
        j+=2;
        hex_string[j] = 0;
    } else{
        hex_string[DEBUG_MSG_MAX_SIZE-1] = 0;
    }
}