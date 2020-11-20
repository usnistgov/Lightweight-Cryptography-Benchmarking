#include "subterranean_mem_compact.h"

//#define DEBUG_MODE

#ifdef DEBUG_MODE
#include "subterranean_mem_compact_debug.h"
#endif

/**
* Subterranean round function
* The input state is updated with the new state.
*/
void subterranean_round(unsigned char state[SUBTERRANEAN_BYTE_SIZE]){
    unsigned char i;
    unsigned char temp_0, temp_1, temp_2;
    unsigned char temp_state[SUBTERRANEAN_BYTE_SIZE];
    
    /* Chi step*/
    for(i = 0; i < (SUBTERRANEAN_BYTE_SIZE - 2); i++){
        temp_0 = ((state[i] >> 1) | (state[i+1] << 7)) & 0xFF;
        temp_1 = ((state[i] >> 2) | (state[i+1] << 6)) & 0xFF;
        temp_state[i] = state[i] ^ ((~ temp_0) & temp_1);
    }
    temp_0 = ((state[i] >> 1) | (state[i+1] << 7)) & 0xFF;
    temp_1 = ((state[i] >> 2) | (state[i+1] << 6)| (state[0] << 7)) & 0xFF;
    temp_state[i] = state[i] ^ ((~ temp_0) & temp_1);
    i+=1;
    temp_0 = (state[0] >> 0) & 0x01;
    temp_1 = (state[0] >> 1) & 0x01;
    temp_state[i] = state[i] ^ ((~ temp_0) & temp_1);
    
    /* Iota step*/
    temp_state[0] ^= 1;
    
    
    /* Theta step*/
    temp_0 = temp_state[0];
    for(i = 0; i < (SUBTERRANEAN_BYTE_SIZE - 2); i++){
        temp_1 = ((temp_state[i] >> 3) | (temp_state[i+1] << 5)) & 0xFF;
        temp_state[i] = temp_state[i] ^ temp_1 ^ temp_state[i+1];
    }
    temp_1 = ((temp_state[i] >> 3) | (temp_state[i+1] << 5) | (temp_0 << 6)) & 0xFF;
    temp_2 = ((temp_state[i+1] >> 0) | (temp_0 << 1)) & 0xFF;
    temp_state[i] = temp_state[i] ^ temp_1  ^ temp_2;
    i+= 1;
    temp_1 = (temp_0 >> 2) & 0x01;
    temp_2 = (temp_0 >> 7) & 0x01;
    temp_state[i] = temp_state[i] ^ temp_1  ^ temp_2;
    
    
    /* Pi step*/
    state[0] = (((temp_state[10] >> 4) & 1)) << 1;
    state[0] = (state[0] | ((temp_state[9] >> 0) & 1)) << 1;
    state[0] = (state[0] | ((temp_state[7] >> 4) & 1)) << 1;
    state[0] = (state[0] | ((temp_state[6] >> 0) & 1)) << 1;
    state[0] = (state[0] | ((temp_state[4] >> 4) & 1)) << 1;
    state[0] = (state[0] | ((temp_state[3] >> 0) & 1)) << 1;
    state[0] = (state[0] | ((temp_state[1] >> 4) & 1)) << 1;
    state[0] = (state[0] | ((temp_state[0] >> 0) & 1));
    state[1] = (((temp_state[22] >> 4) & 1)) << 1;
    state[1] = (state[1] | ((temp_state[21] >> 0) & 1)) << 1;
    state[1] = (state[1] | ((temp_state[19] >> 4) & 1)) << 1;
    state[1] = (state[1] | ((temp_state[18] >> 0) & 1)) << 1;
    state[1] = (state[1] | ((temp_state[16] >> 4) & 1)) << 1;
    state[1] = (state[1] | ((temp_state[15] >> 0) & 1)) << 1;
    state[1] = (state[1] | ((temp_state[13] >> 4) & 1)) << 1;
    state[1] = (state[1] | ((temp_state[12] >> 0) & 1));
    state[2] = (((temp_state[2] >> 3) & 1)) << 1;
    state[2] = (state[2] | ((temp_state[0] >> 7) & 1)) << 1;
    state[2] = (state[2] | ((temp_state[31] >> 4) & 1)) << 1;
    state[2] = (state[2] | ((temp_state[30] >> 0) & 1)) << 1;
    state[2] = (state[2] | ((temp_state[28] >> 4) & 1)) << 1;
    state[2] = (state[2] | ((temp_state[27] >> 0) & 1)) << 1;
    state[2] = (state[2] | ((temp_state[25] >> 4) & 1)) << 1;
    state[2] = (state[2] | ((temp_state[24] >> 0) & 1));
    state[3] = (((temp_state[14] >> 3) & 1)) << 1;
    state[3] = (state[3] | ((temp_state[12] >> 7) & 1)) << 1;
    state[3] = (state[3] | ((temp_state[11] >> 3) & 1)) << 1;
    state[3] = (state[3] | ((temp_state[9] >> 7) & 1)) << 1;
    state[3] = (state[3] | ((temp_state[8] >> 3) & 1)) << 1;
    state[3] = (state[3] | ((temp_state[6] >> 7) & 1)) << 1;
    state[3] = (state[3] | ((temp_state[5] >> 3) & 1)) << 1;
    state[3] = (state[3] | ((temp_state[3] >> 7) & 1));
    state[4] = (((temp_state[26] >> 3) & 1)) << 1;
    state[4] = (state[4] | ((temp_state[24] >> 7) & 1)) << 1;
    state[4] = (state[4] | ((temp_state[23] >> 3) & 1)) << 1;
    state[4] = (state[4] | ((temp_state[21] >> 7) & 1)) << 1;
    state[4] = (state[4] | ((temp_state[20] >> 3) & 1)) << 1;
    state[4] = (state[4] | ((temp_state[18] >> 7) & 1)) << 1;
    state[4] = (state[4] | ((temp_state[17] >> 3) & 1)) << 1;
    state[4] = (state[4] | ((temp_state[15] >> 7) & 1));
    state[5] = (((temp_state[6] >> 2) & 1)) << 1;
    state[5] = (state[5] | ((temp_state[4] >> 6) & 1)) << 1;
    state[5] = (state[5] | ((temp_state[3] >> 2) & 1)) << 1;
    state[5] = (state[5] | ((temp_state[1] >> 6) & 1)) << 1;
    state[5] = (state[5] | ((temp_state[0] >> 2) & 1)) << 1;
    state[5] = (state[5] | ((temp_state[30] >> 7) & 1)) << 1;
    state[5] = (state[5] | ((temp_state[29] >> 3) & 1)) << 1;
    state[5] = (state[5] | ((temp_state[27] >> 7) & 1));
    state[6] = (((temp_state[18] >> 2) & 1)) << 1;
    state[6] = (state[6] | ((temp_state[16] >> 6) & 1)) << 1;
    state[6] = (state[6] | ((temp_state[15] >> 2) & 1)) << 1;
    state[6] = (state[6] | ((temp_state[13] >> 6) & 1)) << 1;
    state[6] = (state[6] | ((temp_state[12] >> 2) & 1)) << 1;
    state[6] = (state[6] | ((temp_state[10] >> 6) & 1)) << 1;
    state[6] = (state[6] | ((temp_state[9] >> 2) & 1)) << 1;
    state[6] = (state[6] | ((temp_state[7] >> 6) & 1));
    state[7] = (((temp_state[30] >> 2) & 1)) << 1;
    state[7] = (state[7] | ((temp_state[28] >> 6) & 1)) << 1;
    state[7] = (state[7] | ((temp_state[27] >> 2) & 1)) << 1;
    state[7] = (state[7] | ((temp_state[25] >> 6) & 1)) << 1;
    state[7] = (state[7] | ((temp_state[24] >> 2) & 1)) << 1;
    state[7] = (state[7] | ((temp_state[22] >> 6) & 1)) << 1;
    state[7] = (state[7] | ((temp_state[21] >> 2) & 1)) << 1;
    state[7] = (state[7] | ((temp_state[19] >> 6) & 1));
    state[8] = (((temp_state[10] >> 1) & 1)) << 1;
    state[8] = (state[8] | ((temp_state[8] >> 5) & 1)) << 1;
    state[8] = (state[8] | ((temp_state[7] >> 1) & 1)) << 1;
    state[8] = (state[8] | ((temp_state[5] >> 5) & 1)) << 1;
    state[8] = (state[8] | ((temp_state[4] >> 1) & 1)) << 1;
    state[8] = (state[8] | ((temp_state[2] >> 5) & 1)) << 1;
    state[8] = (state[8] | ((temp_state[1] >> 1) & 1)) << 1;
    state[8] = (state[8] | ((temp_state[31] >> 6) & 1));
    state[9] = (((temp_state[22] >> 1) & 1)) << 1;
    state[9] = (state[9] | ((temp_state[20] >> 5) & 1)) << 1;
    state[9] = (state[9] | ((temp_state[19] >> 1) & 1)) << 1;
    state[9] = (state[9] | ((temp_state[17] >> 5) & 1)) << 1;
    state[9] = (state[9] | ((temp_state[16] >> 1) & 1)) << 1;
    state[9] = (state[9] | ((temp_state[14] >> 5) & 1)) << 1;
    state[9] = (state[9] | ((temp_state[13] >> 1) & 1)) << 1;
    state[9] = (state[9] | ((temp_state[11] >> 5) & 1));
    state[10] = (((temp_state[2] >> 0) & 1)) << 1;
    state[10] = (state[10] | ((temp_state[0] >> 4) & 1)) << 1;
    state[10] = (state[10] | ((temp_state[31] >> 1) & 1)) << 1;
    state[10] = (state[10] | ((temp_state[29] >> 5) & 1)) << 1;
    state[10] = (state[10] | ((temp_state[28] >> 1) & 1)) << 1;
    state[10] = (state[10] | ((temp_state[26] >> 5) & 1)) << 1;
    state[10] = (state[10] | ((temp_state[25] >> 1) & 1)) << 1;
    state[10] = (state[10] | ((temp_state[23] >> 5) & 1));
    state[11] = (((temp_state[14] >> 0) & 1)) << 1;
    state[11] = (state[11] | ((temp_state[12] >> 4) & 1)) << 1;
    state[11] = (state[11] | ((temp_state[11] >> 0) & 1)) << 1;
    state[11] = (state[11] | ((temp_state[9] >> 4) & 1)) << 1;
    state[11] = (state[11] | ((temp_state[8] >> 0) & 1)) << 1;
    state[11] = (state[11] | ((temp_state[6] >> 4) & 1)) << 1;
    state[11] = (state[11] | ((temp_state[5] >> 0) & 1)) << 1;
    state[11] = (state[11] | ((temp_state[3] >> 4) & 1));
    state[12] = (((temp_state[26] >> 0) & 1)) << 1;
    state[12] = (state[12] | ((temp_state[24] >> 4) & 1)) << 1;
    state[12] = (state[12] | ((temp_state[23] >> 0) & 1)) << 1;
    state[12] = (state[12] | ((temp_state[21] >> 4) & 1)) << 1;
    state[12] = (state[12] | ((temp_state[20] >> 0) & 1)) << 1;
    state[12] = (state[12] | ((temp_state[18] >> 4) & 1)) << 1;
    state[12] = (state[12] | ((temp_state[17] >> 0) & 1)) << 1;
    state[12] = (state[12] | ((temp_state[15] >> 4) & 1));
    state[13] = (((temp_state[5] >> 7) & 1)) << 1;
    state[13] = (state[13] | ((temp_state[4] >> 3) & 1)) << 1;
    state[13] = (state[13] | ((temp_state[2] >> 7) & 1)) << 1;
    state[13] = (state[13] | ((temp_state[1] >> 3) & 1)) << 1;
    state[13] = (state[13] | ((temp_state[32] >> 0) & 1)) << 1;
    state[13] = (state[13] | ((temp_state[30] >> 4) & 1)) << 1;
    state[13] = (state[13] | ((temp_state[29] >> 0) & 1)) << 1;
    state[13] = (state[13] | ((temp_state[27] >> 4) & 1));
    state[14] = (((temp_state[17] >> 7) & 1)) << 1;
    state[14] = (state[14] | ((temp_state[16] >> 3) & 1)) << 1;
    state[14] = (state[14] | ((temp_state[14] >> 7) & 1)) << 1;
    state[14] = (state[14] | ((temp_state[13] >> 3) & 1)) << 1;
    state[14] = (state[14] | ((temp_state[11] >> 7) & 1)) << 1;
    state[14] = (state[14] | ((temp_state[10] >> 3) & 1)) << 1;
    state[14] = (state[14] | ((temp_state[8] >> 7) & 1)) << 1;
    state[14] = (state[14] | ((temp_state[7] >> 3) & 1));
    state[15] = (((temp_state[29] >> 7) & 1)) << 1;
    state[15] = (state[15] | ((temp_state[28] >> 3) & 1)) << 1;
    state[15] = (state[15] | ((temp_state[26] >> 7) & 1)) << 1;
    state[15] = (state[15] | ((temp_state[25] >> 3) & 1)) << 1;
    state[15] = (state[15] | ((temp_state[23] >> 7) & 1)) << 1;
    state[15] = (state[15] | ((temp_state[22] >> 3) & 1)) << 1;
    state[15] = (state[15] | ((temp_state[20] >> 7) & 1)) << 1;
    state[15] = (state[15] | ((temp_state[19] >> 3) & 1));
    state[16] = (((temp_state[9] >> 6) & 1)) << 1;
    state[16] = (state[16] | ((temp_state[8] >> 2) & 1)) << 1;
    state[16] = (state[16] | ((temp_state[6] >> 6) & 1)) << 1;
    state[16] = (state[16] | ((temp_state[5] >> 2) & 1)) << 1;
    state[16] = (state[16] | ((temp_state[3] >> 6) & 1)) << 1;
    state[16] = (state[16] | ((temp_state[2] >> 2) & 1)) << 1;
    state[16] = (state[16] | ((temp_state[0] >> 6) & 1)) << 1;
    state[16] = (state[16] | ((temp_state[31] >> 3) & 1));
    state[17] = (((temp_state[21] >> 6) & 1)) << 1;
    state[17] = (state[17] | ((temp_state[20] >> 2) & 1)) << 1;
    state[17] = (state[17] | ((temp_state[18] >> 6) & 1)) << 1;
    state[17] = (state[17] | ((temp_state[17] >> 2) & 1)) << 1;
    state[17] = (state[17] | ((temp_state[15] >> 6) & 1)) << 1;
    state[17] = (state[17] | ((temp_state[14] >> 2) & 1)) << 1;
    state[17] = (state[17] | ((temp_state[12] >> 6) & 1)) << 1;
    state[17] = (state[17] | ((temp_state[11] >> 2) & 1));
    state[18] = (((temp_state[1] >> 5) & 1)) << 1;
    state[18] = (state[18] | ((temp_state[0] >> 1) & 1)) << 1;
    state[18] = (state[18] | ((temp_state[30] >> 6) & 1)) << 1;
    state[18] = (state[18] | ((temp_state[29] >> 2) & 1)) << 1;
    state[18] = (state[18] | ((temp_state[27] >> 6) & 1)) << 1;
    state[18] = (state[18] | ((temp_state[26] >> 2) & 1)) << 1;
    state[18] = (state[18] | ((temp_state[24] >> 6) & 1)) << 1;
    state[18] = (state[18] | ((temp_state[23] >> 2) & 1));
    state[19] = (((temp_state[13] >> 5) & 1)) << 1;
    state[19] = (state[19] | ((temp_state[12] >> 1) & 1)) << 1;
    state[19] = (state[19] | ((temp_state[10] >> 5) & 1)) << 1;
    state[19] = (state[19] | ((temp_state[9] >> 1) & 1)) << 1;
    state[19] = (state[19] | ((temp_state[7] >> 5) & 1)) << 1;
    state[19] = (state[19] | ((temp_state[6] >> 1) & 1)) << 1;
    state[19] = (state[19] | ((temp_state[4] >> 5) & 1)) << 1;
    state[19] = (state[19] | ((temp_state[3] >> 1) & 1));
    state[20] = (((temp_state[25] >> 5) & 1)) << 1;
    state[20] = (state[20] | ((temp_state[24] >> 1) & 1)) << 1;
    state[20] = (state[20] | ((temp_state[22] >> 5) & 1)) << 1;
    state[20] = (state[20] | ((temp_state[21] >> 1) & 1)) << 1;
    state[20] = (state[20] | ((temp_state[19] >> 5) & 1)) << 1;
    state[20] = (state[20] | ((temp_state[18] >> 1) & 1)) << 1;
    state[20] = (state[20] | ((temp_state[16] >> 5) & 1)) << 1;
    state[20] = (state[20] | ((temp_state[15] >> 1) & 1));
    state[21] = (((temp_state[5] >> 4) & 1)) << 1;
    state[21] = (state[21] | ((temp_state[4] >> 0) & 1)) << 1;
    state[21] = (state[21] | ((temp_state[2] >> 4) & 1)) << 1;
    state[21] = (state[21] | ((temp_state[1] >> 0) & 1)) << 1;
    state[21] = (state[21] | ((temp_state[31] >> 5) & 1)) << 1;
    state[21] = (state[21] | ((temp_state[30] >> 1) & 1)) << 1;
    state[21] = (state[21] | ((temp_state[28] >> 5) & 1)) << 1;
    state[21] = (state[21] | ((temp_state[27] >> 1) & 1));
    state[22] = (((temp_state[17] >> 4) & 1)) << 1;
    state[22] = (state[22] | ((temp_state[16] >> 0) & 1)) << 1;
    state[22] = (state[22] | ((temp_state[14] >> 4) & 1)) << 1;
    state[22] = (state[22] | ((temp_state[13] >> 0) & 1)) << 1;
    state[22] = (state[22] | ((temp_state[11] >> 4) & 1)) << 1;
    state[22] = (state[22] | ((temp_state[10] >> 0) & 1)) << 1;
    state[22] = (state[22] | ((temp_state[8] >> 4) & 1)) << 1;
    state[22] = (state[22] | ((temp_state[7] >> 0) & 1));
    state[23] = (((temp_state[29] >> 4) & 1)) << 1;
    state[23] = (state[23] | ((temp_state[28] >> 0) & 1)) << 1;
    state[23] = (state[23] | ((temp_state[26] >> 4) & 1)) << 1;
    state[23] = (state[23] | ((temp_state[25] >> 0) & 1)) << 1;
    state[23] = (state[23] | ((temp_state[23] >> 4) & 1)) << 1;
    state[23] = (state[23] | ((temp_state[22] >> 0) & 1)) << 1;
    state[23] = (state[23] | ((temp_state[20] >> 4) & 1)) << 1;
    state[23] = (state[23] | ((temp_state[19] >> 0) & 1));
    state[24] = (((temp_state[9] >> 3) & 1)) << 1;
    state[24] = (state[24] | ((temp_state[7] >> 7) & 1)) << 1;
    state[24] = (state[24] | ((temp_state[6] >> 3) & 1)) << 1;
    state[24] = (state[24] | ((temp_state[4] >> 7) & 1)) << 1;
    state[24] = (state[24] | ((temp_state[3] >> 3) & 1)) << 1;
    state[24] = (state[24] | ((temp_state[1] >> 7) & 1)) << 1;
    state[24] = (state[24] | ((temp_state[0] >> 3) & 1)) << 1;
    state[24] = (state[24] | ((temp_state[31] >> 0) & 1));
    state[25] = (((temp_state[21] >> 3) & 1)) << 1;
    state[25] = (state[25] | ((temp_state[19] >> 7) & 1)) << 1;
    state[25] = (state[25] | ((temp_state[18] >> 3) & 1)) << 1;
    state[25] = (state[25] | ((temp_state[16] >> 7) & 1)) << 1;
    state[25] = (state[25] | ((temp_state[15] >> 3) & 1)) << 1;
    state[25] = (state[25] | ((temp_state[13] >> 7) & 1)) << 1;
    state[25] = (state[25] | ((temp_state[12] >> 3) & 1)) << 1;
    state[25] = (state[25] | ((temp_state[10] >> 7) & 1));
    state[26] = (((temp_state[1] >> 2) & 1)) << 1;
    state[26] = (state[26] | ((temp_state[31] >> 7) & 1)) << 1;
    state[26] = (state[26] | ((temp_state[30] >> 3) & 1)) << 1;
    state[26] = (state[26] | ((temp_state[28] >> 7) & 1)) << 1;
    state[26] = (state[26] | ((temp_state[27] >> 3) & 1)) << 1;
    state[26] = (state[26] | ((temp_state[25] >> 7) & 1)) << 1;
    state[26] = (state[26] | ((temp_state[24] >> 3) & 1)) << 1;
    state[26] = (state[26] | ((temp_state[22] >> 7) & 1));
    state[27] = (((temp_state[13] >> 2) & 1)) << 1;
    state[27] = (state[27] | ((temp_state[11] >> 6) & 1)) << 1;
    state[27] = (state[27] | ((temp_state[10] >> 2) & 1)) << 1;
    state[27] = (state[27] | ((temp_state[8] >> 6) & 1)) << 1;
    state[27] = (state[27] | ((temp_state[7] >> 2) & 1)) << 1;
    state[27] = (state[27] | ((temp_state[5] >> 6) & 1)) << 1;
    state[27] = (state[27] | ((temp_state[4] >> 2) & 1)) << 1;
    state[27] = (state[27] | ((temp_state[2] >> 6) & 1));
    state[28] = (((temp_state[25] >> 2) & 1)) << 1;
    state[28] = (state[28] | ((temp_state[23] >> 6) & 1)) << 1;
    state[28] = (state[28] | ((temp_state[22] >> 2) & 1)) << 1;
    state[28] = (state[28] | ((temp_state[20] >> 6) & 1)) << 1;
    state[28] = (state[28] | ((temp_state[19] >> 2) & 1)) << 1;
    state[28] = (state[28] | ((temp_state[17] >> 6) & 1)) << 1;
    state[28] = (state[28] | ((temp_state[16] >> 2) & 1)) << 1;
    state[28] = (state[28] | ((temp_state[14] >> 6) & 1));
    state[29] = (((temp_state[5] >> 1) & 1)) << 1;
    state[29] = (state[29] | ((temp_state[3] >> 5) & 1)) << 1;
    state[29] = (state[29] | ((temp_state[2] >> 1) & 1)) << 1;
    state[29] = (state[29] | ((temp_state[0] >> 5) & 1)) << 1;
    state[29] = (state[29] | ((temp_state[31] >> 2) & 1)) << 1;
    state[29] = (state[29] | ((temp_state[29] >> 6) & 1)) << 1;
    state[29] = (state[29] | ((temp_state[28] >> 2) & 1)) << 1;
    state[29] = (state[29] | ((temp_state[26] >> 6) & 1));
    state[30] = (((temp_state[17] >> 1) & 1)) << 1;
    state[30] = (state[30] | ((temp_state[15] >> 5) & 1)) << 1;
    state[30] = (state[30] | ((temp_state[14] >> 1) & 1)) << 1;
    state[30] = (state[30] | ((temp_state[12] >> 5) & 1)) << 1;
    state[30] = (state[30] | ((temp_state[11] >> 1) & 1)) << 1;
    state[30] = (state[30] | ((temp_state[9] >> 5) & 1)) << 1;
    state[30] = (state[30] | ((temp_state[8] >> 1) & 1)) << 1;
    state[30] = (state[30] | ((temp_state[6] >> 5) & 1));
    state[31] = (((temp_state[29] >> 1) & 1)) << 1;
    state[31] = (state[31] | ((temp_state[27] >> 5) & 1)) << 1;
    state[31] = (state[31] | ((temp_state[26] >> 1) & 1)) << 1;
    state[31] = (state[31] | ((temp_state[24] >> 5) & 1)) << 1;
    state[31] = (state[31] | ((temp_state[23] >> 1) & 1)) << 1;
    state[31] = (state[31] | ((temp_state[21] >> 5) & 1)) << 1;
    state[31] = (state[31] | ((temp_state[20] >> 1) & 1)) << 1;
    state[31] = (state[31] | ((temp_state[18] >> 5) & 1));
    state[32] = (temp_state[30] >> 5) & 1;
}

/**
* Fills Subterranean with 0's
*/
void subterranean_init(unsigned char state[SUBTERRANEAN_BYTE_SIZE]){
    unsigned char i;
    for(i = 0; i < SUBTERRANEAN_BYTE_SIZE; i++){
        state[i] = 0;
    }
}

/**
* Perform a duplex with empty input
*/
void subterranean_duplex_empty(unsigned char state[SUBTERRANEAN_BYTE_SIZE]){
    /* s <= R(s) */
    subterranean_round(state);
    /* sbar <= sbar + (1||0*) */
    state[0] ^=  1 << 1;
}

/**
* Perform a simple duplex
*/
void subterranean_duplex_simple(unsigned char state[SUBTERRANEAN_BYTE_SIZE], const unsigned char * sigma, const unsigned char size_bytes){
    /* s <= R(s) */
    subterranean_round(state);
    /* sbar <= sbar + sigma */
    if(size_bytes >= 1){
        state[0] ^=  ((sigma[0] >> 0) & 1) << 1;
        state[22] ^=  ((sigma[0] >> 1) & 1) << 0;
        state[17] ^=  ((sigma[0] >> 2) & 1) << 0;
        state[4] ^=  ((sigma[0] >> 3) & 1) << 3;
        state[31] ^=  ((sigma[0] >> 4) & 1) << 1;
        state[16] ^=  ((sigma[0] >> 5) & 1) << 6;
        state[24] ^=  ((sigma[0] >> 6) & 1) << 5;
        state[29] ^=  ((sigma[0] >> 7) & 1) << 2;
    }
    if(size_bytes >= 2){
        state[8] ^=  ((sigma[1] >> 0) & 1) << 0;
        state[26] ^=  ((sigma[1] >> 1) & 1) << 5;
        state[27] ^=  ((sigma[1] >> 2) & 1) << 7;
        state[23] ^=  ((sigma[1] >> 3) & 1) << 0;
        state[0] ^=  ((sigma[1] >> 4) & 1) << 2;
        state[11] ^=  ((sigma[1] >> 5) & 1) << 7;
        state[1] ^=  ((sigma[1] >> 6) & 1) << 7;
        state[8] ^=  ((sigma[1] >> 7) & 1) << 6;
    }
    if(size_bytes >= 3){
        state[30] ^=  ((sigma[2] >> 0) & 1) << 1;
        state[1] ^=  ((sigma[2] >> 1) & 1) << 3;
        state[17] ^=  ((sigma[2] >> 2) & 1) << 1;
        state[26] ^=  ((sigma[2] >> 3) & 1) << 3;
        state[16] ^=  ((sigma[2] >> 4) & 1) << 0;
        state[21] ^=  ((sigma[2] >> 5) & 1) << 1;
        state[23] ^=  ((sigma[2] >> 6) & 1) << 5;
        state[13] ^=  ((sigma[2] >> 7) & 1) << 7;
    }
    if(size_bytes >= 4){
        state[0] ^=  ((sigma[3] >> 0) & 1) << 4;
        state[23] ^=  ((sigma[3] >> 1) & 1) << 6;
        state[3] ^=  ((sigma[3] >> 2) & 1) << 6;
        state[17] ^=  ((sigma[3] >> 3) & 1) << 4;
        state[28] ^=  ((sigma[3] >> 4) & 1) << 1;
        state[2] ^=  ((sigma[3] >> 5) & 1) << 6;
        state[2] ^=  ((sigma[3] >> 6) & 1) << 1;
        state[20] ^=  ((sigma[3] >> 7) & 1) << 5;
    }
    /* sbar <= sbar + (1||0*) */
    if(size_bytes == 0){
        state[0] ^=  1 << 1;
    } else if(size_bytes == 1){
        state[8] ^=  1 << 0;
    } else if(size_bytes == 2){
        state[30] ^=  1 << 1;
    } else if(size_bytes == 3){
        state[0] ^=  1 << 4;
    } else if(size_bytes == 4){
        state[32] ^=  1 << 0;
    }
}

/**
* Perform a duplex for encryption
*/
void subterranean_duplex_encrypt(unsigned char state[SUBTERRANEAN_BYTE_SIZE], unsigned char * value_out, const unsigned char * sigma, const unsigned char size_bytes){
    /* value_out <= sbar + sigma */
    if(size_bytes >= 1){
        value_out[0] =  (((state[29] >> 2) ^ (state[2] >> 7) ^ (sigma[0] >> 7)) & 1) << 1;
        value_out[0] =  (value_out[0] | (((state[24] >> 5) ^ (state[7] >> 4) ^ (sigma[0] >> 6)) & 1)) << 1;
        value_out[0] =  (value_out[0] | (((state[16] >> 6) ^ (state[15] >> 3) ^ (sigma[0] >> 5)) & 1)) << 1;
        value_out[0] =  (value_out[0] | (((state[31] >> 1) ^ (state[1] >> 0) ^ (sigma[0] >> 4)) & 1)) << 1;
        value_out[0] =  (value_out[0] | (((state[4] >> 3) ^ (state[27] >> 6) ^ (sigma[0] >> 3)) & 1)) << 1;
        value_out[0] =  (value_out[0] | (((state[17] >> 0) ^ (state[15] >> 1) ^ (sigma[0] >> 2)) & 1)) << 1;
        value_out[0] =  (value_out[0] | (((state[22] >> 0) ^ (state[10] >> 1) ^ (sigma[0] >> 1)) & 1)) << 1;
        value_out[0] =  (value_out[0] | (((state[0] >> 1) ^ (state[32] >> 0) ^ (sigma[0] >> 0)) & 1));
    }
    if(size_bytes >= 2){
        value_out[1] =  (((state[8] >> 6) ^ (state[23] >> 3) ^ (sigma[1] >> 7)) & 1) << 1;
        value_out[1] =  (value_out[1] | (((state[1] >> 7) ^ (state[30] >> 2) ^ (sigma[1] >> 6)) & 1)) << 1;
        value_out[1] =  (value_out[1] | (((state[11] >> 7) ^ (state[20] >> 2) ^ (sigma[1] >> 5)) & 1)) << 1;
        value_out[1] =  (value_out[1] | (((state[0] >> 2) ^ (state[31] >> 7) ^ (sigma[1] >> 4)) & 1)) << 1;
        value_out[1] =  (value_out[1] | (((state[23] >> 0) ^ (state[9] >> 1) ^ (sigma[1] >> 3)) & 1)) << 1;
        value_out[1] =  (value_out[1] | (((state[27] >> 7) ^ (state[4] >> 2) ^ (sigma[1] >> 2)) & 1)) << 1;
        value_out[1] =  (value_out[1] | (((state[26] >> 5) ^ (state[5] >> 4) ^ (sigma[1] >> 1)) & 1)) << 1;
        value_out[1] =  (value_out[1] | (((state[8] >> 0) ^ (state[24] >> 1) ^ (sigma[1] >> 0)) & 1));
    }
    if(size_bytes >= 3){
        value_out[2] =  (((state[13] >> 7) ^ (state[18] >> 2) ^ (sigma[2] >> 7)) & 1) << 1;
        value_out[2] =  (value_out[2] | (((state[23] >> 5) ^ (state[8] >> 4) ^ (sigma[2] >> 6)) & 1)) << 1;
        value_out[2] =  (value_out[2] | (((state[21] >> 1) ^ (state[11] >> 0) ^ (sigma[2] >> 5)) & 1)) << 1;
        value_out[2] =  (value_out[2] | (((state[16] >> 0) ^ (state[16] >> 1) ^ (sigma[2] >> 4)) & 1)) << 1;
        value_out[2] =  (value_out[2] | (((state[26] >> 3) ^ (state[5] >> 6) ^ (sigma[2] >> 3)) & 1)) << 1;
        value_out[2] =  (value_out[2] | (((state[17] >> 1) ^ (state[15] >> 0) ^ (sigma[2] >> 2)) & 1)) << 1;
        value_out[2] =  (value_out[2] | (((state[1] >> 3) ^ (state[30] >> 6) ^ (sigma[2] >> 1)) & 1)) << 1;
        value_out[2] =  (value_out[2] | (((state[30] >> 1) ^ (state[2] >> 0) ^ (sigma[2] >> 0)) & 1));
    }
    if(size_bytes >= 4){
        value_out[3] =  (((state[20] >> 5) ^ (state[11] >> 4) ^ (sigma[3] >> 7)) & 1) << 1;
        value_out[3] =  (value_out[3] | (((state[2] >> 1) ^ (state[30] >> 0) ^ (sigma[3] >> 6)) & 1)) << 1;
        value_out[3] =  (value_out[3] | (((state[2] >> 6) ^ (state[29] >> 3) ^ (sigma[3] >> 5)) & 1)) << 1;
        value_out[3] =  (value_out[3] | (((state[28] >> 1) ^ (state[4] >> 0) ^ (sigma[3] >> 4)) & 1)) << 1;
        value_out[3] =  (value_out[3] | (((state[17] >> 4) ^ (state[14] >> 5) ^ (sigma[3] >> 3)) & 1)) << 1;
        value_out[3] =  (value_out[3] | (((state[3] >> 6) ^ (state[28] >> 3) ^ (sigma[3] >> 2)) & 1)) << 1;
        value_out[3] =  (value_out[3] | (((state[23] >> 6) ^ (state[8] >> 3) ^ (sigma[3] >> 1)) & 1)) << 1;
        value_out[3] =  (value_out[3] | (((state[0] >> 4) ^ (state[31] >> 5) ^ (sigma[3] >> 0)) & 1));
    }
    /* s <= R(s) */
    subterranean_round(state);
    /* sbar <= sbar + sigma */
    if(size_bytes >= 1){
        state[0] ^=  ((sigma[0] >> 0) & 1) << 1;
        state[22] ^=  ((sigma[0] >> 1) & 1) << 0;
        state[17] ^=  ((sigma[0] >> 2) & 1) << 0;
        state[4] ^=  ((sigma[0] >> 3) & 1) << 3;
        state[31] ^=  ((sigma[0] >> 4) & 1) << 1;
        state[16] ^=  ((sigma[0] >> 5) & 1) << 6;
        state[24] ^=  ((sigma[0] >> 6) & 1) << 5;
        state[29] ^=  ((sigma[0] >> 7) & 1) << 2;
    }
    if(size_bytes >= 2){
        state[8] ^=  ((sigma[1] >> 0) & 1) << 0;
        state[26] ^=  ((sigma[1] >> 1) & 1) << 5;
        state[27] ^=  ((sigma[1] >> 2) & 1) << 7;
        state[23] ^=  ((sigma[1] >> 3) & 1) << 0;
        state[0] ^=  ((sigma[1] >> 4) & 1) << 2;
        state[11] ^=  ((sigma[1] >> 5) & 1) << 7;
        state[1] ^=  ((sigma[1] >> 6) & 1) << 7;
        state[8] ^=  ((sigma[1] >> 7) & 1) << 6;
    }
    if(size_bytes >= 3){
        state[30] ^=  ((sigma[2] >> 0) & 1) << 1;
        state[1] ^=  ((sigma[2] >> 1) & 1) << 3;
        state[17] ^=  ((sigma[2] >> 2) & 1) << 1;
        state[26] ^=  ((sigma[2] >> 3) & 1) << 3;
        state[16] ^=  ((sigma[2] >> 4) & 1) << 0;
        state[21] ^=  ((sigma[2] >> 5) & 1) << 1;
        state[23] ^=  ((sigma[2] >> 6) & 1) << 5;
        state[13] ^=  ((sigma[2] >> 7) & 1) << 7;
    }
    if(size_bytes >= 4){
        state[0] ^=  ((sigma[3] >> 0) & 1) << 4;
        state[23] ^=  ((sigma[3] >> 1) & 1) << 6;
        state[3] ^=  ((sigma[3] >> 2) & 1) << 6;
        state[17] ^=  ((sigma[3] >> 3) & 1) << 4;
        state[28] ^=  ((sigma[3] >> 4) & 1) << 1;
        state[2] ^=  ((sigma[3] >> 5) & 1) << 6;
        state[2] ^=  ((sigma[3] >> 6) & 1) << 1;
        state[20] ^=  ((sigma[3] >> 7) & 1) << 5;
    }
    /* sbar <= sbar + (1||0*) */
    if(size_bytes == 0){
        state[0] ^=  1 << 1;
    } else if(size_bytes == 1){
        state[8] ^=  1 << 0;
    } else if(size_bytes == 2){
        state[30] ^=  1 << 1;
    } else if(size_bytes == 3){
        state[0] ^=  1 << 4;
    } else if(size_bytes == 4){
        state[32] ^=  1 << 0;
    }
}

/**
* Perform a duplex for decryption
*/
void subterranean_duplex_decrypt(unsigned char state[SUBTERRANEAN_BYTE_SIZE], unsigned char * value_out, const unsigned char * sigma, const unsigned char size_bytes){
    /* value_out <= sbar + sigma */
    if(size_bytes >= 1){
        value_out[0] =  (((state[29] >> 2) ^ (state[2] >> 7) ^ (sigma[0] >> 7)) & 1) << 1;
        value_out[0] =  (value_out[0] | (((state[24] >> 5) ^ (state[7] >> 4) ^ (sigma[0] >> 6)) & 1)) << 1;
        value_out[0] =  (value_out[0] | (((state[16] >> 6) ^ (state[15] >> 3) ^ (sigma[0] >> 5)) & 1)) << 1;
        value_out[0] =  (value_out[0] | (((state[31] >> 1) ^ (state[1] >> 0) ^ (sigma[0] >> 4)) & 1)) << 1;
        value_out[0] =  (value_out[0] | (((state[4] >> 3) ^ (state[27] >> 6) ^ (sigma[0] >> 3)) & 1)) << 1;
        value_out[0] =  (value_out[0] | (((state[17] >> 0) ^ (state[15] >> 1) ^ (sigma[0] >> 2)) & 1)) << 1;
        value_out[0] =  (value_out[0] | (((state[22] >> 0) ^ (state[10] >> 1) ^ (sigma[0] >> 1)) & 1)) << 1;
        value_out[0] =  (value_out[0] | (((state[0] >> 1) ^ (state[32] >> 0) ^ (sigma[0] >> 0)) & 1));
    }
    if(size_bytes >= 2){
        value_out[1] =  (((state[8] >> 6) ^ (state[23] >> 3) ^ (sigma[1] >> 7)) & 1) << 1;
        value_out[1] =  (value_out[1] | (((state[1] >> 7) ^ (state[30] >> 2) ^ (sigma[1] >> 6)) & 1)) << 1;
        value_out[1] =  (value_out[1] | (((state[11] >> 7) ^ (state[20] >> 2) ^ (sigma[1] >> 5)) & 1)) << 1;
        value_out[1] =  (value_out[1] | (((state[0] >> 2) ^ (state[31] >> 7) ^ (sigma[1] >> 4)) & 1)) << 1;
        value_out[1] =  (value_out[1] | (((state[23] >> 0) ^ (state[9] >> 1) ^ (sigma[1] >> 3)) & 1)) << 1;
        value_out[1] =  (value_out[1] | (((state[27] >> 7) ^ (state[4] >> 2) ^ (sigma[1] >> 2)) & 1)) << 1;
        value_out[1] =  (value_out[1] | (((state[26] >> 5) ^ (state[5] >> 4) ^ (sigma[1] >> 1)) & 1)) << 1;
        value_out[1] =  (value_out[1] | (((state[8] >> 0) ^ (state[24] >> 1) ^ (sigma[1] >> 0)) & 1));
    }
    if(size_bytes >= 3){
        value_out[2] =  (((state[13] >> 7) ^ (state[18] >> 2) ^ (sigma[2] >> 7)) & 1) << 1;
        value_out[2] =  (value_out[2] | (((state[23] >> 5) ^ (state[8] >> 4) ^ (sigma[2] >> 6)) & 1)) << 1;
        value_out[2] =  (value_out[2] | (((state[21] >> 1) ^ (state[11] >> 0) ^ (sigma[2] >> 5)) & 1)) << 1;
        value_out[2] =  (value_out[2] | (((state[16] >> 0) ^ (state[16] >> 1) ^ (sigma[2] >> 4)) & 1)) << 1;
        value_out[2] =  (value_out[2] | (((state[26] >> 3) ^ (state[5] >> 6) ^ (sigma[2] >> 3)) & 1)) << 1;
        value_out[2] =  (value_out[2] | (((state[17] >> 1) ^ (state[15] >> 0) ^ (sigma[2] >> 2)) & 1)) << 1;
        value_out[2] =  (value_out[2] | (((state[1] >> 3) ^ (state[30] >> 6) ^ (sigma[2] >> 1)) & 1)) << 1;
        value_out[2] =  (value_out[2] | (((state[30] >> 1) ^ (state[2] >> 0) ^ (sigma[2] >> 0)) & 1));
    }
    if(size_bytes >= 4){
        value_out[3] =  (((state[20] >> 5) ^ (state[11] >> 4) ^ (sigma[3] >> 7)) & 1) << 1;
        value_out[3] =  (value_out[3] | (((state[2] >> 1) ^ (state[30] >> 0) ^ (sigma[3] >> 6)) & 1)) << 1;
        value_out[3] =  (value_out[3] | (((state[2] >> 6) ^ (state[29] >> 3) ^ (sigma[3] >> 5)) & 1)) << 1;
        value_out[3] =  (value_out[3] | (((state[28] >> 1) ^ (state[4] >> 0) ^ (sigma[3] >> 4)) & 1)) << 1;
        value_out[3] =  (value_out[3] | (((state[17] >> 4) ^ (state[14] >> 5) ^ (sigma[3] >> 3)) & 1)) << 1;
        value_out[3] =  (value_out[3] | (((state[3] >> 6) ^ (state[28] >> 3) ^ (sigma[3] >> 2)) & 1)) << 1;
        value_out[3] =  (value_out[3] | (((state[23] >> 6) ^ (state[8] >> 3) ^ (sigma[3] >> 1)) & 1)) << 1;
        value_out[3] =  (value_out[3] | (((state[0] >> 4) ^ (state[31] >> 5) ^ (sigma[3] >> 0)) & 1));
    }
    /* s <= R(s) */
    subterranean_round(state);
    /* sbar <= sbar + value_out */
    if(size_bytes >= 1){
        state[0] ^=  ((value_out[0] >> 0) & 1) << 1;
        state[22] ^=  ((value_out[0] >> 1) & 1) << 0;
        state[17] ^=  ((value_out[0] >> 2) & 1) << 0;
        state[4] ^=  ((value_out[0] >> 3) & 1) << 3;
        state[31] ^=  ((value_out[0] >> 4) & 1) << 1;
        state[16] ^=  ((value_out[0] >> 5) & 1) << 6;
        state[24] ^=  ((value_out[0] >> 6) & 1) << 5;
        state[29] ^=  ((value_out[0] >> 7) & 1) << 2;
    }
    if(size_bytes >= 2){
        state[8] ^=  ((value_out[1] >> 0) & 1) << 0;
        state[26] ^=  ((value_out[1] >> 1) & 1) << 5;
        state[27] ^=  ((value_out[1] >> 2) & 1) << 7;
        state[23] ^=  ((value_out[1] >> 3) & 1) << 0;
        state[0] ^=  ((value_out[1] >> 4) & 1) << 2;
        state[11] ^=  ((value_out[1] >> 5) & 1) << 7;
        state[1] ^=  ((value_out[1] >> 6) & 1) << 7;
        state[8] ^=  ((value_out[1] >> 7) & 1) << 6;
    }
    if(size_bytes >= 3){
        state[30] ^=  ((value_out[2] >> 0) & 1) << 1;
        state[1] ^=  ((value_out[2] >> 1) & 1) << 3;
        state[17] ^=  ((value_out[2] >> 2) & 1) << 1;
        state[26] ^=  ((value_out[2] >> 3) & 1) << 3;
        state[16] ^=  ((value_out[2] >> 4) & 1) << 0;
        state[21] ^=  ((value_out[2] >> 5) & 1) << 1;
        state[23] ^=  ((value_out[2] >> 6) & 1) << 5;
        state[13] ^=  ((value_out[2] >> 7) & 1) << 7;
    }
    if(size_bytes >= 4){
        state[0] ^=  ((value_out[3] >> 0) & 1) << 4;
        state[23] ^=  ((value_out[3] >> 1) & 1) << 6;
        state[3] ^=  ((value_out[3] >> 2) & 1) << 6;
        state[17] ^=  ((value_out[3] >> 3) & 1) << 4;
        state[28] ^=  ((value_out[3] >> 4) & 1) << 1;
        state[2] ^=  ((value_out[3] >> 5) & 1) << 6;
        state[2] ^=  ((value_out[3] >> 6) & 1) << 1;
        state[20] ^=  ((value_out[3] >> 7) & 1) << 5;
    }
    /* sbar <= sbar + (1||0*) */
    if(size_bytes == 0){
        state[0] ^=  1 << 1;
    } else if(size_bytes == 1){
        state[8] ^=  1 << 0;
    } else if(size_bytes == 2){
        state[30] ^=  1 << 1;
    } else if(size_bytes == 3){
        state[0] ^=  1 << 4;
    } else if(size_bytes == 4){
        state[32] ^=  1 << 0;
    }
}

/**
* Perform a simple squeeze
*/
void subterranean_squeeze_simple(unsigned char state[SUBTERRANEAN_BYTE_SIZE], unsigned char value_out[4]){
    /* y <= sbar */
    value_out[0] =  (((state[29] >> 2) ^ (state[2] >> 7)) & 1) << 1;
    value_out[0] =  (value_out[0] | (((state[24] >> 5) ^ (state[7] >> 4)) & 1)) << 1;
    value_out[0] =  (value_out[0] | (((state[16] >> 6) ^ (state[15] >> 3)) & 1)) << 1;
    value_out[0] =  (value_out[0] | (((state[31] >> 1) ^ (state[1] >> 0)) & 1)) << 1;
    value_out[0] =  (value_out[0] | (((state[4] >> 3) ^ (state[27] >> 6)) & 1)) << 1;
    value_out[0] =  (value_out[0] | (((state[17] >> 0) ^ (state[15] >> 1)) & 1)) << 1;
    value_out[0] =  (value_out[0] | (((state[22] >> 0) ^ (state[10] >> 1)) & 1)) << 1;
    value_out[0] =  (value_out[0] | (((state[0] >> 1) ^ (state[32] >> 0)) & 1));
    value_out[1] =  (((state[8] >> 6) ^ (state[23] >> 3)) & 1) << 1;
    value_out[1] =  (value_out[1] | (((state[1] >> 7) ^ (state[30] >> 2)) & 1)) << 1;
    value_out[1] =  (value_out[1] | (((state[11] >> 7) ^ (state[20] >> 2)) & 1)) << 1;
    value_out[1] =  (value_out[1] | (((state[0] >> 2) ^ (state[31] >> 7)) & 1)) << 1;
    value_out[1] =  (value_out[1] | (((state[23] >> 0) ^ (state[9] >> 1)) & 1)) << 1;
    value_out[1] =  (value_out[1] | (((state[27] >> 7) ^ (state[4] >> 2)) & 1)) << 1;
    value_out[1] =  (value_out[1] | (((state[26] >> 5) ^ (state[5] >> 4)) & 1)) << 1;
    value_out[1] =  (value_out[1] | (((state[8] >> 0) ^ (state[24] >> 1)) & 1));
    value_out[2] =  (((state[13] >> 7) ^ (state[18] >> 2)) & 1) << 1;
    value_out[2] =  (value_out[2] | (((state[23] >> 5) ^ (state[8] >> 4)) & 1)) << 1;
    value_out[2] =  (value_out[2] | (((state[21] >> 1) ^ (state[11] >> 0)) & 1)) << 1;
    value_out[2] =  (value_out[2] | (((state[16] >> 0) ^ (state[16] >> 1)) & 1)) << 1;
    value_out[2] =  (value_out[2] | (((state[26] >> 3) ^ (state[5] >> 6)) & 1)) << 1;
    value_out[2] =  (value_out[2] | (((state[17] >> 1) ^ (state[15] >> 0)) & 1)) << 1;
    value_out[2] =  (value_out[2] | (((state[1] >> 3) ^ (state[30] >> 6)) & 1)) << 1;
    value_out[2] =  (value_out[2] | (((state[30] >> 1) ^ (state[2] >> 0)) & 1));
    value_out[3] =  (((state[20] >> 5) ^ (state[11] >> 4)) & 1) << 1;
    value_out[3] =  (value_out[3] | (((state[2] >> 1) ^ (state[30] >> 0)) & 1)) << 1;
    value_out[3] =  (value_out[3] | (((state[2] >> 6) ^ (state[29] >> 3)) & 1)) << 1;
    value_out[3] =  (value_out[3] | (((state[28] >> 1) ^ (state[4] >> 0)) & 1)) << 1;
    value_out[3] =  (value_out[3] | (((state[17] >> 4) ^ (state[14] >> 5)) & 1)) << 1;
    value_out[3] =  (value_out[3] | (((state[3] >> 6) ^ (state[28] >> 3)) & 1)) << 1;
    value_out[3] =  (value_out[3] | (((state[23] >> 6) ^ (state[8] >> 3)) & 1)) << 1;
    value_out[3] =  (value_out[3] | (((state[0] >> 4) ^ (state[31] >> 5)) & 1));
    /* s <= R(s) */
    subterranean_round(state);
    /* sbar <= sbar + (1||0*) */
    state[0]  ^=  1 << 1;
}

/**
* Perform a absorb unkeyed
*/
void subterranean_absorb_unkeyed(unsigned char state[SUBTERRANEAN_BYTE_SIZE], const unsigned char * value_in, const unsigned long long value_in_length){
    unsigned long long i;
    
    /* Let x[n] be X split in 8-bit blocks, with last block strictly shorter */
    i = 0;
    /*
    * for all blocks of x[n] do
    *     duplexSimple(x[i])
    *     duplexEmpty()
    */
    if(value_in_length > 0){
        while(i <= value_in_length - 1){
            subterranean_duplex_simple(state, &value_in[i], 1);
            subterranean_duplex_empty(state);
            i += 1;
        }
    }
    subterranean_duplex_simple(state, &value_in[i], 0);
    subterranean_duplex_empty(state);
}

/**
* Perform a absorb keyed
*/
void subterranean_absorb_keyed(unsigned char state[SUBTERRANEAN_BYTE_SIZE], const unsigned char * value_in, const unsigned long long value_in_length){
    unsigned long long i;
    
    /* Let x[n] be X split in 32-bit blocks, with last block strictly shorter */
    i = 0;
    /*
    * for all blocks of x[n] do
    *     duplexSimple(x[i])
    */
    if(value_in_length >= 4){
        while(i <= value_in_length - 4){
            subterranean_duplex_simple(state, &value_in[i], 4);
            i += 4;
        }
    }
    if(value_in_length % 4 == 1){
        subterranean_duplex_simple(state, &value_in[i], 1);
    } else if(value_in_length % 4 == 2){
        subterranean_duplex_simple(state, &value_in[i], 2);
    } else if(value_in_length % 4 == 3){
        subterranean_duplex_simple(state, &value_in[i], 3);
    } else{
        subterranean_duplex_simple(state, &value_in[i], 0);
    }
}

/**
* Perform a absorb encryption
*/
void subterranean_absorb_encrypt(unsigned char state[SUBTERRANEAN_BYTE_SIZE], unsigned char * value_out, const unsigned char * value_in, const unsigned long long value_in_length){
    unsigned long long i;
    
    /* Let x[n] be X split in 32-bit blocks, with last block strictly shorter */
    i = 0;
    /*
    * for all blocks of x[n] do
    *     temp <= duplexEncrypt(x[i])
    *     Y <= Y || temp
    */
    if(value_in_length >= 4){
        while(i <= value_in_length - 4){
            subterranean_duplex_encrypt(state, &value_out[i], &value_in[i], 4);
            i += 4;
        }
    }
    if(value_in_length % 4 == 1){
        subterranean_duplex_encrypt(state, &value_out[i], &value_in[i], 1);
    } else if(value_in_length % 4 == 2){
        subterranean_duplex_encrypt(state, &value_out[i], &value_in[i], 2);
    } else if(value_in_length % 4 == 3){
        subterranean_duplex_encrypt(state, &value_out[i], &value_in[i], 3);
    } else{
        subterranean_duplex_encrypt(state, &value_out[i], &value_in[i], 0);
    }
}

/**
* Perform a absorb decryption
*
* Internal memory cost = 1 unsigned long long + subterranean_duplex_decrypt
* 37 unsigned char + 1 unsigned long long
*/
void subterranean_absorb_decrypt(unsigned char state[SUBTERRANEAN_BYTE_SIZE], unsigned char * value_out, const unsigned char * value_in, const unsigned long long value_in_length){
    unsigned long long i;
    
    /* Let x[n] be X split in 32-bit blocks, with last block strictly shorter */
    i = 0;
    /*
    * for all blocks of x[n] do
    *     temp <= duplexDecrypt(x[i])
    *     Y <= Y || temp
    */
    if(value_in_length >= 4){
        while(i <= value_in_length - 4){
            subterranean_duplex_decrypt(state, &value_out[i], &value_in[i], 4);
            i += 4;
        }
    }
    if(value_in_length % 4 == 1){
        subterranean_duplex_decrypt(state, &value_out[i], &value_in[i], 1);
    } else if(value_in_length % 4 == 2){
        subterranean_duplex_decrypt(state, &value_out[i], &value_in[i], 2);
    } else if(value_in_length % 4 == 3){
        subterranean_duplex_decrypt(state, &value_out[i], &value_in[i], 3);
    } else{
        subterranean_duplex_decrypt(state, &value_out[i], &value_in[i], 0);
    }
}

/**
* Performs blank
*/
void subterranean_blank(unsigned char state[SUBTERRANEAN_BYTE_SIZE], const unsigned char r_calls){
    unsigned char i;
    
    /* for r times do duplex(0*) */
    for(i = 0; i < r_calls; i++){
        subterranean_duplex_empty(state);
    }
    
}

/**
* Performs a squeeze
*
* Internal memory cost = 4 unsigned char + 2 unsigned long long + subterranean_squeeze_simple
* 41 unsigned char + 2 unsigned long long
*/
void subterranean_squeeze(unsigned char state[SUBTERRANEAN_BYTE_SIZE], unsigned char * value_out, const unsigned long long value_out_length){
    unsigned char temp[4];
    unsigned long long i, j;
    
    /*
     * while |Z| < l do
     *     temp <= SqueezeSimple()
     *     Z <= Z||temp
     */
    i = 0;
    if(value_out_length > 4){
        while(i < (value_out_length-4)){
            subterranean_squeeze_simple(state, &value_out[i]);
            i += 4;
        }
    }
    subterranean_squeeze_simple(state, temp);
    for(j = 0; i < value_out_length; i++){
        value_out[i] = temp[j++];
    }
}

/**
* Performs a XOF initialization
*/
void subterranean_xof_init(unsigned char state[SUBTERRANEAN_BYTE_SIZE]){
    /* S <= Subterranean() */
    subterranean_init(state);
}

/**
* Performs a XOF update
*/
void subterranean_xof_update(unsigned char state[SUBTERRANEAN_BYTE_SIZE], const unsigned char * m, const unsigned long long m_length){
    subterranean_absorb_unkeyed(state, m, m_length);
}

/**
* Performs a XOF finalization
*/
void subterranean_xof_finalize(unsigned char state[SUBTERRANEAN_BYTE_SIZE], unsigned char * z, const unsigned long long z_length){
    /* S.blank(8) */
    subterranean_blank(state, 8);
    /* Z <= S.squeeze(l) */
    subterranean_squeeze(state, z, z_length);
}

/**
* Performs a XOF operation directly into one message
*/
void subterranean_xof_direct(unsigned char * z, const unsigned long long z_length, const unsigned char * m, const unsigned long long m_length){
    unsigned char state[SUBTERRANEAN_BYTE_SIZE];
    /* S <= Subterranean() */
    subterranean_init(state);

    subterranean_absorb_unkeyed(state, m, m_length);
    
    /* S.blank(8) */
    subterranean_blank(state, 8);
    /* Z <= S.squeeze(l) */
    subterranean_squeeze(state, z, z_length);
}

/**
* Performs a deck initialization
*/
void subterranean_deck_init(unsigned char state[SUBTERRANEAN_BYTE_SIZE], const unsigned char * k, const unsigned long long k_length){
    /* S <= Subterranean() */
    subterranean_init(state);
    /* S.absorb(K,MAC) */
    subterranean_absorb_keyed(state, k, k_length);
}

/**
* Performs a deck update
*/
void subterranean_deck_update(unsigned char state[SUBTERRANEAN_BYTE_SIZE], const unsigned char * m, const unsigned long long m_length){
    subterranean_absorb_keyed(state, m, m_length);
}

/**
* Performs a deck finalization
*/
void subterranean_deck_finalize(unsigned char state[SUBTERRANEAN_BYTE_SIZE], unsigned char * z, const unsigned long long z_length){
    /* S.blank(8) */
    subterranean_blank(state, 8);
    /* Z <= S.squeeze(l) */
    subterranean_squeeze(state, z, z_length);
}

/**
* Performs a deck directly into one message and one key
*/
void subterranean_deck_direct(unsigned char * z, const unsigned long long z_length, const unsigned char * k, const unsigned long long k_length, const unsigned char * m, const unsigned long long m_length){
    unsigned char state[SUBTERRANEAN_BYTE_SIZE];
    /* S <= Subterranean() */
    subterranean_init(state);
    /* S.absorb(K,MAC) */
    subterranean_absorb_keyed(state, k, k_length);
    
    subterranean_absorb_keyed(state, m, m_length);
    
    /* S.blank(8) */
    subterranean_blank(state, 8);
    /* Z <= S.squeeze(l) */
    subterranean_squeeze(state, z, z_length);
}

/**
* Performs a SAE initialization 
*/
void subterranean_SAE_start(unsigned char state[SUBTERRANEAN_BYTE_SIZE], const unsigned char * k, const unsigned long long k_length, const unsigned char * n, const unsigned long long n_length){
    /* S <= Subterranean() */
    subterranean_init(state);
    /* S.absorb(K) */
    subterranean_absorb_keyed(state, k, k_length);
    /* S.absorb(N) */
    subterranean_absorb_keyed(state, n, n_length);
    /* S.blank(8) */
    subterranean_blank(state, 8);
}

/**
* Performs a SAE encryption after the initialization 
*/
int subterranean_SAE_wrap_encrypt(unsigned char state[SUBTERRANEAN_BYTE_SIZE], unsigned char * y, unsigned char * t, const unsigned long long t_length, const unsigned char * a, const unsigned long long a_length, const unsigned char * x, const unsigned long long x_length){
    /* S.absorb(A,MAC) */
    subterranean_absorb_keyed(state, a, a_length);
    /* Y <= S.absorb(X,op) */
    subterranean_absorb_encrypt(state, y, x, x_length);
    /* S.blank(8) */
    subterranean_blank(state, 8);
    /* T <= S.squeeze(tau) */
    subterranean_squeeze(state, t, t_length);
    return 0;
}

/**
* Performs a SAE decryption after the initialization 
*/
int subterranean_SAE_wrap_decrypt(unsigned char state[SUBTERRANEAN_BYTE_SIZE], unsigned char * y, unsigned char * t, const unsigned char * t_prime, const unsigned long long t_length, const unsigned char * a, const unsigned long long a_length, const unsigned char * x, const unsigned long long x_length){
    unsigned long long i;
    unsigned char tag_different;
    /* S.absorb(A,MAC) */
    subterranean_absorb_keyed(state, a, a_length);
    /* Y <= S.absorb(X,op) */
    subterranean_absorb_decrypt(state, y, x, x_length);
    /* S.blank(8) */
    subterranean_blank(state, 8);
    /* T <= S.squeeze(tau) */
    subterranean_squeeze(state, t, t_length);
    /* if op = decrypt AND (tag != new_tag) then (Y,T) = (*,*) */
    tag_different = 0;
    /* Check if tags are matching */
    for(i = 0; i < t_length; i++){
        tag_different |= t[i] ^ t_prime[i];
    }
    /* If tags do not match */
    if(tag_different != 0){
        for(i = 0; i < x_length; i++){ 
            y[i] = 0;
        }
        for(i = 0; i < t_length; i++){ 
            t[i] = 0;
        }
        return -1;
    }
    else
        return 0;
}

/**
* Performs a SAE encryption directly for one key, one message and one authenticated data
*/
int subterranean_SAE_direct_encrypt(unsigned char * y, unsigned char * t, const unsigned char * k, const unsigned long long k_length, const unsigned char * n, const unsigned long long n_length, const unsigned long long t_length, const unsigned char * a, const unsigned long long a_length, const unsigned char * x, const unsigned long long x_length){
    unsigned char state[SUBTERRANEAN_BYTE_SIZE];
    /* S <= Subterranean() */
    subterranean_init(state);
    /* S.absorb(K) */
    subterranean_absorb_keyed(state, k, k_length);
    /* S.absorb(N) */
    subterranean_absorb_keyed(state, n, n_length);
    /* S.blank(8) */
    subterranean_blank(state, 8);
    /* S.absorb(A,MAC) */
    subterranean_absorb_keyed(state, a, a_length);
    /* Y <= S.absorb(X,op) */
    subterranean_absorb_encrypt(state, y, x, x_length);
    /* S.blank(8) */
    subterranean_blank(state, 8);
    /* T <= S.squeeze(tau) */
    subterranean_squeeze(state, t, t_length);
    return 0;
}

/**
* Performs a SAE decryption directly for one key, one message and one authenticated data
*/
int subterranean_SAE_direct_decrypt(unsigned char * y, unsigned char * t, const unsigned char * k, const unsigned long long k_length, const unsigned char * n, const unsigned long long n_length, const unsigned char * t_prime, const unsigned long long t_length, const unsigned char * a, const unsigned long long a_length, const unsigned char * x, const unsigned long long x_length){
    unsigned char state[SUBTERRANEAN_BYTE_SIZE];
    unsigned long long i;
    unsigned char tag_different;
    /* S <= Subterranean() */
    subterranean_init(state);
    /* S.absorb(K) */
    subterranean_absorb_keyed(state, k, k_length);
    /* S.absorb(N) */
    subterranean_absorb_keyed(state, n, n_length);
    /* S.blank(8) */
    subterranean_blank(state, 8);
    /* S.absorb(A,MAC) */
    subterranean_absorb_keyed(state, a, a_length);
    /* Y <= S.absorb(X,op) */
    subterranean_absorb_decrypt(state, y, x, x_length);
    /* S.blank(8) */
    subterranean_blank(state, 8);
    /* T <= S.squeeze(tau) */
    subterranean_squeeze(state, t, t_length);
    /* if op = decrypt AND (tag != new_tag) then (Y,T) = (*,*) */
    tag_different = 0;
    /* Check if tags are matching */
    for(i = 0; i < t_length; i++){
        tag_different |= t[i] ^ t_prime[i];
    }
    /* If tags do not match */
    if(tag_different != 0){
        for(i = 0; i < x_length; i++){ 
            y[i] = 0;
        }
        for(i = 0; i < t_length; i++){ 
            t[i] = 0;
        }
        return -1;
    }
    else
        return 0;
}
