#include "options.h" //options.h to define BLOCKSIZE

#if BLOCKSIZE == 64
#	define ROUNDS 27

	//size of a word in bytes
	//(pt and ct size = 2 words = 1 block)
#	define WSZ 4

	//number of words for key
#	define M 4

#elif BLOCKSIZE == 128
#	define ROUNDS 32

	//size of a word in bytes
	//(pt and ct size = 2 words = 1 block)
#	define WSZ 8

	//number of words for key
#	define M 2

#endif

#define CARRY(r, a, b) ( ((a>>7)&(b>>7)) | ((a>>7)&(!(r>>7))) | ((!(r>>7))&(b>>7)) )

typedef unsigned char u8;
typedef unsigned int u32;

void blockcipher_encrypt (u8 *ct, const u8 *pt, const u8 *K)
{
    u8 L[(ROUNDS+M-2)*WSZ] = { 0 };
    u8 RK[ROUNDS*WSZ] = { 0 };
	u8 carry;
	u8 ct_temp[2*WSZ] = { 0 };

	//RK0 = K0	
	for(u8 j=0; j<WSZ; j++){
		RK[j] = K[j];
	}
	
	//initial Ls
	for(u8 i=0; i<M-1; i++){
		for(u8 j=0; j<WSZ; j++){
			L[i*WSZ+j] = K[(i+1)*WSZ+j];
		}
	}
	
	//Key Schedule
    for (u8 i=0; i<ROUNDS-1; i++){
		carry = 0;
		
		//L[i+m-1] = (ROR(L[i], 8) + RK[i]) ^ i
		for(u8 j=0; j<WSZ; j++){
			L[(i+M-1)*WSZ+j] = L[i*WSZ+((j+1)%WSZ)] + RK[i*WSZ+j];
			
			//add carry
			L[(i+M-1)*WSZ+j] += carry;
			
			//set next carry
			carry = CARRY(L[(i+M-1)*WSZ+j], L[i*WSZ+((j+1)%WSZ)], RK[i*WSZ+j]);
			
			if(j==0){
				L[(i+M-1)*WSZ+j] ^= i;
			}
		}
		
        //RK[i+1] = ROL(RK[i], 3) ^ L[i+m-1]
		for(u8 j=0; j<WSZ; j++){
			RK[(i+1)*WSZ+j] = (RK[i*WSZ+j]<<3 | RK[i*WSZ+((j+WSZ-1)%WSZ)]>>5) ^ L[(i+M-1)*WSZ+j];
		}
    }
	
	//Encryption 
	for(u8 j=0; j<2*WSZ; j++){
		ct[j] = pt[j]; //copy pt to ct
	}

    for(u8 i=0; i<ROUNDS; i++){
		carry = 0;
		
		//ct[1] = (ROR(ct[1], 8) + ct[0]) ^ RK[i]
		for(u8 j=0; j<WSZ; j++){
			ct_temp[WSZ+j] = (ct[WSZ+((j+1)%WSZ)] + ct[j]);
			
			//add carry
			ct_temp[WSZ+j] += carry;
			
			//set next carry
			carry = (ct_temp[WSZ+j] < ct[WSZ+((j+1)%WSZ)]) || (ct_temp[WSZ+j] < ct[j]);
			
			
			ct_temp[WSZ+j] ^= RK[i*WSZ+j];
		}
		
		//ct[0] = ROL(ct[0], 3) ^ ct[1]
		for(u8 j=0; j<WSZ; j++){
			ct_temp[j] = ( ct[j]<<3 | ct[(j+WSZ-1)%WSZ]>>5) ^ ct_temp[WSZ+j];
		}
		
		//copy ct from temp
		for(u8 j=0; j<2*WSZ; j++){
			ct[j] = ct_temp[j];
		}
    }
}