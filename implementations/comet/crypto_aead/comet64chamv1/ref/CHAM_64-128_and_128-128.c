#include "options.h" //options.h to define BLOCKSIZE

#if BLOCKSIZE == 64
#	define ROUNDS 80

	//size of a word in bytes
	//(pt and ct size = 4 words = 1 block)
#	define WSZ 2

	//number of words for key (K/W)
#	define M 8

#elif BLOCKSIZE == 128
#	define ROUNDS 80

	//size of a word in bytes
	//(pt and ct size = 4 words = 1 block)
#	define WSZ 4

	//number of words for key (K/W)
#	define M 4

#endif

#define CARRY(r, a, b) ( ((a>>7)&(b>>7)) | ((a>>7)&(!(r>>7))) | ((!(r>>7))&(b>>7)) )

typedef unsigned char u8;
typedef unsigned int u32;

void blockcipher_encrypt (u8 *ct, const u8 *pt, const u8 *key)
{	
	u8 rk[2*M*WSZ];
		
	//key expansion
	u8 rol_1[WSZ];		//Rotation Left 1
	u8 rol_8[WSZ];		//Rotation Left 8
	u8 rol_11[WSZ];		//Rotation Left 11


	for(u8 i=0; i<M; i++){
		
		for(u8 j=0; j<WSZ; j++){
			rol_1[j] = (key[i*WSZ+j] << 1) | (key[i*WSZ+((j+WSZ-1)%WSZ)] >> 7);
			rol_8[j] = key[i*WSZ+((j+WSZ-1)%WSZ)];
			rol_11[j] = (key[i*WSZ+((j+WSZ-1)%WSZ)] << 3) | (key[i*WSZ+((j+WSZ-2)%WSZ)] >>5);
		}
		
		for(u8 j=0; j<WSZ; j++){
			rk[i*WSZ+j] = key[i*WSZ+j] ^ rol_1[j] ^ rol_8[j];
			
			rk[((i+M) ^ 1)*WSZ+j] = key[i*WSZ+j] ^ rol_1[j] ^ rol_11[j]; 
		}
	}
	
	//encryption
	u8 rol[WSZ];
	u8 tmp1[WSZ];
	u8 tmp2[WSZ];
	u8 carry;
	u8 ct_prev[4*WSZ];
	
	//ct_prev = pt
	for(u8 j=0; j<4*WSZ; j++){
		ct_prev[j] = pt[j];
	}
	
	for(u8 i=0; i<ROUNDS; i++){
		
		//ct[0..2] = ct_prev[1..3]
		for(u8 j=0; j<3*WSZ; j++){
			ct[j] = ct_prev[WSZ+j];
		}
		
		if(i%2 == 0){
			
			//ROL_1(ct_prev[1])
			for(u8 j=0; j<WSZ; j++){
				rol[j] = (ct_prev[WSZ+j] << 1) | (ct_prev[WSZ+((j+WSZ-1)%WSZ)] >> 7);				
			}
			
			//TMP1 = ROL_1(ct_prev[1]) XOR RK[i]
			for(u8 j=0; j<WSZ; j++){
				tmp1[j] = rol[j] ^ rk[(i % (2 * M))*WSZ+j];
			}
			
			carry = 0;
			//TMP2 = TMP1 + (ct_prev[0] XOR i)
			for(u8 j=0; j<WSZ; j++){
				if(j==0){
					tmp2[j] = tmp1[j] + (ct_prev[j] ^ i);
				} else {
					tmp2[j] = tmp1[j] + ct_prev[j];
				}
				//add carry
				tmp2[j] += carry;
				
				//set next carry
				if(j==0){
					carry = CARRY(tmp2[j], tmp1[j], (ct_prev[j]^i) );
				} else {
					carry = CARRY(tmp2[j], tmp1[j], ct_prev[j]);
				}
			}
			
			//ct[3] = ROL_8(TMP2)
			for(u8 j=0; j<WSZ; j++){
				ct[3*WSZ+j] = tmp2[(j+WSZ-1)%WSZ];
			}
		} else {
			
			//ROL_8(ct_prev[1])
			for(u8 j=0; j<WSZ; j++){
				rol[j] = ct_prev[WSZ+((j+WSZ-1)%WSZ)];
			}
			
			//TMP1 = ROL_8(ct_prev[1]) XOR RK[i]
			for(u8 j=0; j<WSZ; j++){
				tmp1[j] = rol[j] ^ rk[(i % (2 * M))*WSZ+j];
			}
			
			carry = 0;
			//TMP2 = TMP1 + (ct_prev[0] XOR i)
			for(u8 j=0; j<WSZ; j++){
				if(j==0){
					tmp2[j] = tmp1[j] + (ct_prev[j] ^ i);
				} else {
					tmp2[j] = tmp1[j] + ct_prev[j];
				}
				//add carry
				tmp2[j] += carry;
				
				//set next carry
				if(j==0){
					carry = CARRY(tmp2[j], tmp1[j], (ct_prev[j]^i) );
				} else {
					carry = CARRY(tmp2[j], tmp1[j], ct_prev[j]);
				}
			}
			
			//ct[3] = ROL_1(TMP2)
			for(u8 j=0; j<WSZ; j++){
				ct[3*WSZ+j] = (tmp2[j] << 1) | (tmp2[(j+WSZ-1)%WSZ] >> 7);
			}
		}
		
		//ct_prev = ct
		for(u8 j=0; j<4*WSZ; j++){
			ct_prev[j] = ct[j];
		}
	}
	return;
}