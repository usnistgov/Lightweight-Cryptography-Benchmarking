/**
 * Helper functions
 * 
 * @file helpers.h
 * @author Antoon Purnal <antoon.purnal@esat.kuleuven.be>
 */

#ifndef HELPERS_H
#define HELPERS_H

#include "extra_api.h"


void stateCopy(unsigned char a[4][4], unsigned char b[4][4]);
void tweakeyCopy(unsigned char tweakey[TWEAKEY_BLOCKSIZE_RATIO][4][4], unsigned char input[TWEAKEY_BLOCKSIZE_RATIO][4][4]);
void stateToCharArray(unsigned char* array, unsigned char a[4][4]);

#endif
