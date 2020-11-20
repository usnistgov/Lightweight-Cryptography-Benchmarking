/**
 * The Skinny round function and key schedule.
 *
 * We acknowledge the contribution of the SKINNY design team, who have created and published the Skinny reference implementation, which served as a baseline for this file.
 * 
 * @file skinny_round.h
 * @author Antoon Purnal <antoon.purnal@esat.kuleuven.be>
 */

#ifndef SKINNY_ROUND_H
#define SKINNY_ROUND_H

#include "extra_api.h"

void advanceKeySchedule(unsigned char keyCells[TWEAKEY_BLOCKSIZE_RATIO][4][4]);
void reverseKeySchedule(unsigned char keyCells[TWEAKEY_BLOCKSIZE_RATIO][4][4]);

void skinny_round(unsigned char state[4][4], unsigned char keyCells[TWEAKEY_BLOCKSIZE_RATIO][4][4], int i);
void skinny_round_inv(unsigned char state[4][4], unsigned char keyCells[TWEAKEY_BLOCKSIZE_RATIO][4][4], int i);

#endif /* ifndef SKINNY_ROUND_H */
