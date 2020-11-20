#ifndef _SUBTERRANEAN_MEM_COMPACT_DEBUG_H_
#define _SUBTERRANEAN_MEM_COMPACT_DEBUG_H_

#include <stdio.h>

#define DEBUG_MSG_MAX_SIZE 500

char debug_msg[DEBUG_MSG_MAX_SIZE];

void bytes_to_hex_string(char * hex_string, const unsigned char * in_bytes, const unsigned int in_len){
    unsigned int i, j;
    j = 0;
    for (i = 0; (i < in_len) && (j < DEBUG_MSG_MAX_SIZE); i++){
        sprintf(&hex_string[j], "%02x",in_bytes[i]);
        j+=2;
    }
    if(j < DEBUG_MSG_MAX_SIZE-1){
        hex_string[j] = 0;
    } else{
        hex_string[DEBUG_MSG_MAX_SIZE-1] = 0;
    }
}

#endif