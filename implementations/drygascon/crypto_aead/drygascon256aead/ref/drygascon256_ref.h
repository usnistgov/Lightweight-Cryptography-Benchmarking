/**
DryGascon256
Sebastien Riou, January 27th 2019
c99 ref implementation meant to fit in the supercop framework
*/
#ifndef __DRYGASCON256_H__
#define __DRYGASCON256_H__

#define DRYSPONGE_DBG_EN 0

#define DRYSPONGE_KEYSIZE 32
#define DRYSPONGE_NONCESIZE 16
#define DRYSPONGE_BLOCKSIZE 16
#define DRYSPONGE_CAPACITYSIZE (9*64/8)
#define DRYSPONGE_XSIZE (4*32/8)
#define DRYSPONGE_INIT_ROUNDS 12
#define DRYSPONGE_ROUNDS 8
#define DRYSPONGE_ACCUMULATE_FACTOR 4
#define DRYSPONGE_MPR_INPUT_WIDTH 18

#include "drygascon_ref.h"

#endif
