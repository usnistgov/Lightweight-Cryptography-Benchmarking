
#include "photon.h"

/*################################################################################################################
 
 Circular Left Shift Function (Any direction any number of bits for any number of total Bytes)
 
 ################################################################################################################*/
int gcd( int a, int b){
    if(b== 0)
        return a;
    return gcd(b, a%b);
}


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
int byte_wise_lshift(u8 * value, int pos_byte,int byte_shift_period)
{
    int no_cycle = gcd(byte_shift_period, pos_byte);
    for(int i = 0; i < no_cycle; i++)
    {
        
        for(int j=0; j<byte_shift_period;j++){
            int temp1 = value[i];
            if(((j+1)*(pos_byte))%byte_shift_period != 0){
                value[i] = value[(i+(j + 1) *pos_byte) % byte_shift_period];
                value[(i+(j + 1) * pos_byte) % byte_shift_period] = temp1;
            }
            else
                break;
        }
        
    }
    return 0;
}
int interbytelshift(u8 * value, int pos,int byte_shift_period)
{
    u8 temp1=0, temp2=0;
    int pos_byte=0, i=0;
    if(pos < 0)
        pos = 8 * byte_shift_period + pos;
    pos_byte = pos / 8;
    byte_wise_lshift(value, pos_byte,byte_shift_period);
    pos = pos % 8;
    for(i = 0; i < byte_shift_period; i++)
    {   temp2 = value[i] >> (8 - pos);
        value[i] = inbytelshift(value[i], pos) ^temp2^ temp1;
        temp1 = temp2;
    }
    value[0] = value[0] ^ temp1;
    return 0;
}


/*################################################################################################################
 
 Finite Field Multiplication
 
 ################################################################################################################*/



int alpha_mult(u8 * value)
{
    
    u8 temp1;
    temp1 = value[15]>> 7;
    interbytelshift(value, 1, 16);
    u8 alpha_128[16];
    
    for(int j=0; j<16;j++)
    {
        if(j==0)                       //alpha_128 = x^128 + x^7 + x^2 + x + 1 .
            alpha_128[j]=0x87;
        else
            alpha_128[j]= 0x00;
    }
    if(temp1==1)
    {
        
        value[0] = value[0]^ 0x01;
        for(int i=0;i<16;i++)
            value[i] = value[i]^alpha_128[i];
    }
    return 0;
}

int mult(int c , u8 * value)
{
    
    for(int i=0 ; i<c ;i++)
        alpha_mult(&value[16]);
    return 0;
}

/*################################################################################################################
 
 OrangeZest Hash Processing Function
 
 ################################################################################################################*/


int hash(u8 * X ,const u8 * D ,ul dlen, int a, int b)
{
    ul d,blen=32;int flag =a;
    if(dlen%32==0)
        d = dlen/32;
    else
    {
        d = dlen/32+1;
        flag =b;
    }
    ul i=0;
    while(i<d)
    {
        
        
        
        if (i==d-1)
        {
            mult(flag, X);
            blen= dlen+blen- 32*d;
        }
        for(ul j=0;j<blen;j++)
        {
            if(j<blen)
                X[j] = X[j]^D[32*i+j];
            
        }
        if (blen!= 32)
            X[blen] = X[blen]^0x01;
        if(i!=d-1)
            PHOTON_256_Permutation(X);
        
        i++;
    }
    
    return 0;
}
/*################################################################################################################
 
 OrangeZest FeedBack Function
 
 ################################################################################################################*/

int rho(u8 * S , u8 * Y ,u8 *Z)
{
    alpha_mult(S);
    for(int j=0;j<16;j++)
    {
        Z[j]= Y[j];
        Z[j+16] = Y[j+16]^S[j];
    }
    interbytelshift(Z, 1, 16);
    return 0;
}
/*################################################################################################################
 
 OrangeZest Message/Ciphertext processing Function
 
 ################################################################################################################*/
int txt (u8 * S ,u8 *U ,const u8 * D, u8 * C,ul dlen , int a)
{
    u8  KS[32];
    ul d,blen=32;int flag =1;
    if(dlen%32==0)
        d= dlen/32;
    
    else
    {
        d= dlen/32 +1;
        flag =2;
        
    }
    ul i=0;
    while(i<d)
    {
        if(i==d-1)
        {
            mult(flag, U);
            blen= dlen+blen- 32*d;
        }
        rho(S, U, KS);
        for(int j=0 ;j<16;j++)
            S[j]= U[j+16];
        for(ul j=0; j<blen ; j++)
        {    C[32*i+j] = D[32*i+j]^KS[j];
        }
        if(a==1)
        {
            for(ul j=0 ; j<blen;j++)
            {
                U[j] = U[j]^ C[32*i+j];
            }
            
        }
        else{
            for(ul j=0 ; j<blen;j++)
            {
                U[j] = U[j]^ D[32*i+j];
            }
        }
        if(blen !=32)
            U[blen] = U[blen]^0x01;
        if(i!=d-1){
            PHOTON_256_Permutation(U);
        }
        i++;
        
    }
    return 0;
}
/*################################################################################################################
 
 OrangeZest Tag Generation Function
 
 ################################################################################################################*/
int tag(u8 * X)
{
    
    for(int i=0 ; i<16 ;i++)
    {
        X[i] = X[i]^X[i+16];
        X[i+16]= X[i+16] ^X[i];
        X[i] = X[i] ^ X[i+16];
        
    }
    
    PHOTON_256_Permutation(X);
    return 0;
}
