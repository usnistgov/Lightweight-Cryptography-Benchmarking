#ifndef __PHOTON_H_
#define __PHOTON_H_
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <math.h>

#define ROUND			12
#define D				8
#define S 4
#define WORDFILTER 0xF

void PHOTON_Permutation(unsigned char *State_inout);

#endif /*  end of photon.h */
