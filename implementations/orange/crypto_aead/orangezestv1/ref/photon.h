

#ifndef Header_h
#define Header_h


#endif /* Header_h */
//
//  photon.c
//  photon
//


#ifndef photon_c
#define photon_c

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long ul;


u8 sbox[16] = {12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2};

const u8 MixColMatrix[8][8] = {{ 2,  4,  2, 11,  2,  8,  5,  6},
    {12,  9,  8, 13,  7,  7,  5,  2},
    { 4,  4, 13, 13,  9,  4, 13,  9},
    { 1,  6,  5,  1, 12, 13, 15, 14},
    {15, 12,  9, 13, 14,  5, 14, 13},
    { 9, 14,  5, 15,  4, 12,  9,  6},
    {12,  2,  2, 10,  3,  1,  1, 14},
    {15,  1, 13, 10,  5, 10,  2,  3}};

const u8 RC[8][12] = {{1, 3, 7, 14, 13, 11, 6, 12, 9, 2, 5, 10},
    {0, 2, 6, 15, 12, 10, 7, 13, 8, 3, 4, 11},
    {2, 0, 4, 13, 14, 8, 5, 15, 10, 1, 6, 9},
    {6, 4, 0, 9, 10, 12, 1, 11, 14, 5, 2, 13},
    {14, 12, 8, 1, 2, 4, 9, 3, 6, 13, 10, 5},
    {15, 13, 9, 0, 3, 5, 8, 2, 7, 12, 11, 4},
    {13, 15, 11, 2, 1, 7, 10, 0, 5, 14, 9, 6},
    {9, 11, 15, 6, 5, 3, 14, 4, 1, 10, 13, 2}};


const u8 ReductionPoly = 0x3;
const u8 WORDFILTER = ((u8) 1<<4)-1;

#define CONST_A 0x000000000000000000000001;
#define CONST_M 0x000000000000000000000002;




//............ALL MODULES............


//The function to store four characters to unsigned u16//
void store16(u8 *Bytes, u16 word)
{ int i;
    for (i = 0 ; i < 2 ; i++) {Bytes[i] = (u8)word;  word >>= 8; }
}



//The function to load a u16 to 2 byte array//
u16 load16(u8* Bytes)
{int i; u16 Block;
    Block=0;
    Block = (u16)(Bytes[1]);
    for(i = 0; i < 1; i++) {Block <<= 8; Block = (Block)^(u16)(Bytes[i]);}
    return Block;}











//The function to store four characters to unsigned u32//
void store32(u8 *Bytes, u32 word)
{ int i;
    for (i = 0 ; i < 4 ; i++) {Bytes[i] = (u8)word;  word >>= 8; }
}



//The function to load a u32 to 4 byte array//
u32 load32(u8* Bytes)
{int i; u32 Block;
    Block=0;
    Block = (u32)(Bytes[3]);
    for(i = 0; i < 3; i++) {Block <<= 8; Block = (Block)^(u32)(Bytes[i]);}
    return Block;}



u8 FieldMult(u8 a, u8 b)
{
    u8 x = a, ret = 0;
    u32 i;
    for(i = 0; i < 4; i++) {
        if((b>>i)&1) ret ^= x;
        if((x>>3)&1) {
            x <<= 1;
            x ^= ReductionPoly;
        }
        else x <<= 1;
    }
    return ret&WORDFILTER;
}



u8* AddRC(u8* State, int round)
{
    int i;
    for(i = 0; i < 8; i++)
        State[4*i] ^= RC[i][round];
    
    return State;
}



u8* SubCell(u8* State)
{
    u32 i;
    for(i = 0 ; i < 32 ; i++)
    {
        State[i] = sbox[State[i]&15] ^ ((sbox[State[i] >> 4])<<4);
    }
    return State;
}




u8* ShiftRow(u8* State)
{
    u32 i;
    
    for(i = 0 ; i < 8 ; i++)
    {
        store32(State+4*i, (((load32(State+4*i))>>4*i)|((load32(State+4*i))<<((32-4*i)%32))));
    }
    
    return State;
}



u8 TwoColMult(u8 a0, u8 a1, u8 a2, u8 a3, u8 a4, u8 a5, u8 a6, u8 a7, u32 index)
{
    return (FieldMult((a0&15), MixColMatrix[index][0])^ (FieldMult((a0>>4), MixColMatrix[index][0])<<4) ^ FieldMult((a1&15), MixColMatrix[index][1])^ (FieldMult((a1>>4), MixColMatrix[index][1])<<4) ^ FieldMult((a2&15), MixColMatrix[index][2])^ (FieldMult((a2>>4), MixColMatrix[index][2])<<4) ^ FieldMult((a3&15), MixColMatrix[index][3])^ (FieldMult((a3>>4), MixColMatrix[index][3])<<4) ^ FieldMult((a4&15), MixColMatrix[index][4])^ (FieldMult((a4>>4), MixColMatrix[index][4])<<4) ^ FieldMult((a5&15), MixColMatrix[index][5])^ (FieldMult((a5>>4), MixColMatrix[index][5])<<4)^ FieldMult((a6&15), MixColMatrix[index][6])^ (FieldMult((a6>>4), MixColMatrix[index][6])<<4)^ FieldMult((a7&15), MixColMatrix[index][7])^ (FieldMult((a7>>4), MixColMatrix[index][7])<<4));
    
    
}




u8* MixColumn(u8 *State)
{
    u32 j;
    u8 a0, a1, a2, a3, a4, a5, a6, a7;
    
    for(j = 0 ; j < 4 ; j++)
    {
        a0 =  TwoColMult(State[0+j], State[4+j], State[8+j], State[12+j], State[16+j], State[20+j], State[24+j], State[28+j], 0);
        
        a1 =  TwoColMult(State[0+j], State[4+j], State[8+j], State[12+j], State[16+j], State[20+j], State[24+j], State[28+j], 1);
        
        a2 =  TwoColMult(State[0+j], State[4+j], State[8+j], State[12+j], State[16+j], State[20+j], State[24+j], State[28+j], 2);
        
        a3 =  TwoColMult(State[0+j], State[4+j], State[8+j], State[12+j], State[16+j], State[20+j], State[24+j], State[28+j], 3);
        
        a4 =  TwoColMult(State[0+j], State[4+j], State[8+j], State[12+j], State[16+j], State[20+j], State[24+j], State[28+j], 4);
        
        a5 =  TwoColMult(State[0+j], State[4+j], State[8+j], State[12+j], State[16+j], State[20+j], State[24+j], State[28+j], 5);
        
        a6 =  TwoColMult(State[0+j], State[4+j], State[8+j], State[12+j], State[16+j], State[20+j], State[24+j], State[28+j], 6);
        
        a7 =  TwoColMult(State[0+j], State[4+j], State[8+j], State[12+j], State[16+j], State[20+j], State[24+j], State[28+j], 7);
        
        State[j] = a0;
        State[4+j] = a1;
        State[8+j] = a2;
        State[12+j] = a3;
        State[16+j] = a4;
        State[20+j] = a5;
        State[24+j] = a6;
        State[28+j] = a7;
        
        
    }
    return State;
}



u8* PHOTON_256_Permutation(u8* State)
{
    int i;
    
    for(i = 0; i < 12; i++)
    {
        State = AddRC(State, i);
        State = SubCell(State);
        State = ShiftRow(State);
        State = MixColumn(State);
        
    }
    return State;
}


#endif /* photon */
