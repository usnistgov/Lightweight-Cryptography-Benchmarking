typedef unsigned char u8;
typedef unsigned long long ull;

#include <stdio.h>

/*
#############################################################################################################
################################## Function to Calculate GCD of Two Numbers #################################
#############################################################################################################
*/

int gcd(int a, int b)
{
    if(b == 0)
        return a;
    return gcd(b, a % b);
}

/*
#############################################################################################################
########################### Function to Perform Left Circular Shift inside a Byte ###########################
#############################################################################################################
*/

int inbytelshift(u8 value, int pos)
{
    u8 temp1 = value, temp2 = value;
    if(pos > 0)
    {
        return (((temp1 << pos) & 0xff) | temp2 >> (8 - pos));
    }
    else if(pos < 0)
    {
        return (((temp1 << (8 + pos)) & 0xff) | temp2 >> - pos);
    }
    else
        return value;
}

/*
#############################################################################################################
################## Function to Perform Left Circular Shift inside a Block of Several Bytes ##################
#############################################################################################################
*/

int interbytelshift(u8 * value, int pos, int byte_shift_period)
{
    u8 temp1, temp2;
    int pos_byte, i, j;
    if(pos < 0)
        pos = 8 * byte_shift_period + pos;
    pos_byte = pos / 8;
    for(i = 0; i < gcd(pos_byte, byte_shift_period); i++)
        for(j = 0; j < byte_shift_period; j++)
        {
            temp1 = value[i];
            if(((j + 1) *(byte_shift_period - pos_byte)) % byte_shift_period == 0)
                break;
            else
            {
                value[i] = value[(i + (j + 1) *(byte_shift_period - pos_byte)) % byte_shift_period];
                value[(i + (j + 1) *(byte_shift_period - pos_byte)) % byte_shift_period] = temp1;
            }
        }
    pos = pos % 8;
    temp1 = value[0] >> (8 - pos);
    for(i = 0; i < byte_shift_period; i++)
    {
        temp2 = value[i] >> (8 - pos);
        value[i] = inbytelshift(value[i], pos) ^ temp2;
        if(i > 0)
            value[i - 1] = value[i - 1] ^ temp2;
    }
    value[byte_shift_period - 1] = value[byte_shift_period - 1] ^ temp1;
    return 0;
}

/*
#############################################################################################################
################################# Simon 96 / 96 Block Cipher with 26 Rounds #################################
#############################################################################################################
*/

int SimP_round(u8 *key, u8 *input, u8 *output, ull round)
{
    // z2 sequence for Simon 96 / 96
    ull z[62] = {1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0,
                 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1}, i = 0, j = 0;


    // local variable declaration
    u8 k2[6] = {0}, k1[6] = {0}, k0[6] = {0}, x[6] = {0}, y[6] = {0}, temp[6] = {0}, temp1[6] = {0}, temp2[6] = {0}, temp3[6] = {0};


    // initializing key and input array
    for(i = 0; i < 6; i++)
    {
        k1[i] = key[i];
        k0[i] = key[6 + i];
        x[i] = input[i];
        y[i] = input[6 + i];
    }


    // key schedule and round function for each round
    for(i = 0; i < 26; i++)
    {
        /*
        #############################################################################################################
        ############################################### Key Schedule ################################################
        #############################################################################################################
        */

        for(j = 0; j < 6; j++)
            k2[j] = k1[j];

        interbytelshift(k2, -3, 6);    // 3 bits right circular shift of k1

        for(j = 0; j < 6; j++)
            temp1[j] = k2[j];

        interbytelshift(k2, -1, 6);    // 4 bits right circular shift of k1

        for(j = 0; j < 6; j++)
            temp2[j] = k2[j];

        // calculating value of round key of current value
        for(j = 0; j < 5; j++)
            k2[j] = k0[j] ^ temp1[j] ^ temp2[j] ^ 255;

        k2[5] = k0[5] ^ temp1[5] ^ temp2[5] ^ 252 ^ z[((26 * round) + i) % 62];

        /*
        #############################################################################################################
        ############################################## Round Function ###############################################
        #############################################################################################################
        */

        interbytelshift(x, 1, 6);    // 1 bit left circular shift of x

        for(j = 0; j < 6; j++)
            temp1[j] = x[j];

        interbytelshift(x, 1, 6);    // 2 bits left circular shift of x

        for(j = 0; j < 6; j++)
            temp2[j] = x[j];

        interbytelshift(x, 6, 6);    // 8 bits left circular shift of x

        for(j = 0; j < 6; j++)
            temp3[j] = x[j];

        interbytelshift(x, -8, 6);   // restoring original value of x

        // calculating new value of x
        for(j = 0; j < 6; j++)
            temp[j] = ((temp1[j] & temp3[j]) ^ temp2[j]) ^ y[j] ^ k0[j];

        // updating the values of x and y
        for(j = 0; j < 6; j++)
        {
            y[j] = x[j];
            x[j] = temp[j];
        }

        for(j = 0; j < 6; j++)
        {
            k0[j] = k1[j];
            k1[j] = k2[j];
        }
    }

    // updating output array with final values of x and y
    for(i = 0; i < 6; i++)
    {
        output[i] = x[i];
        output[6 + i] = y[i];
    }

    // updating key array with final values of round keys
    for(i = 0; i < 6; i++)
    {
        key[i] = k1[i];
        key[6 + i] = k0[i];
    }

    return 0;
}

/*
#############################################################################################################
################################## SimP-192 Permutation - 2 Round Feistel ###################################
#############################################################################################################
*/

int SimP_2(u8 *value)
{
    // local variable declaration
    u8 output[12] = {0};
    ull i = 0, j = 0;


    // 2 calls to Simp_round
    for(j = 0; j < 2; j++)
    {
        SimP_round(&value[0], &value[12], output, j);    // Simp_round call

        // calculating input for next Simp_round call
        if(j != 1)
            for(i = 0; i < 12; i++)
            {
                value[12 + i] = value[i];
                value[i] = output[i];
            }
        else
            for(i = 0; i < 12; i++)
                value[12 + i] = output[i];
    }


    return 0;
}

/*
#############################################################################################################
################################## SimP-192 Permutation - 4 Round Feistel ###################################
#############################################################################################################
*/

int SimP_4(u8 *value)
{
    // local variable declaration
    u8 output[12] = {0};
    ull i = 0, j = 0;


    // 4 calls to Simp_round
    for(j = 0; j < 4; j++)
    {
        SimP_round(&value[0], &value[12], output, j);    // Simp_round call

        // calculating input for next Simp_round call
        if(j != 3)
            for(i = 0; i < 12; i++)
            {
                value[12 + i] = value[i];
                value[i] = output[i];
            }
        else
            for(i = 0; i < 12; i++)
                value[12 + i] = output[i];
    }


    return 0;
}
