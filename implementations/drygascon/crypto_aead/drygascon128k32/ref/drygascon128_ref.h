/**
DryGascon128
Sebastien Riou, January 27th 2019
c99 ref implementation meant to fit in the supercop framework
*/
#ifndef __DRYGASCON128_H__
#define __DRYGASCON128_H__

#define DRYSPONGE_DBG_EN 0

#define DRYSPONGE_KEYSIZE 16
#define DRYSPONGE_NONCESIZE 16
#define DRYSPONGE_BLOCKSIZE 16
#define DRYSPONGE_CAPACITYSIZE (5*64/8)
#define DRYSPONGE_XSIZE (4*32/8)
//remove one round because Mix does 1 round merely for processing the upper
//2 bits of the domain separator (because 128+4 mod 10 is 2)
#define DRYSPONGE_INIT_ROUNDS (12-1)
#define DRYSPONGE_ROUNDS (8-1)
#define DRYSPONGE_ACCUMULATE_FACTOR 2
#define DRYSPONGE_MPR_INPUT_WIDTH 10

#include "drygascon_ref.h"

#endif
