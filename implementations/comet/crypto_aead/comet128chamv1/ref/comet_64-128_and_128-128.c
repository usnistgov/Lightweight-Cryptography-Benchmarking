#include <string.h>
#include <stdlib.h>
#include "api.h"

#include "blockcipher.h"

#include "options.h" //options.h to define BLOCKSIZE

#if BLOCKSIZE == 64

	#define MSZ 8

#elif BLOCKSIZE == 128

	#define MSZ 16

#endif


typedef unsigned char u8;		//used for Byte-Arrays
typedef unsigned int u32;		//used for regular counters
typedef unsigned long long ull;	//used for long counters

#define KSZ CRYPTO_KEYBYTES


void E(u8 *ct, const u8 *key, const u8 *pt){
	
	blockcipher_encrypt(ct, pt, key);
	
	return;
}

void init_state_64(u8 *X, u8 *Z, const u8 *K, const u8 *N){
	
	u8 zero[MSZ] = { 0 };
	
	//X <- E(K, 0)
	E(X, K, zero);
	
	//Z <- 0^(|K|-r)||N
	memset(Z, 0, KSZ);
	memcpy(Z, N, CRYPTO_NPUBBYTES);
	
	//Z <- K XOR 0^(|K|-r)||N
	for(u32 j=0; j<KSZ; j++){
		Z[j] ^= K[j];
	}
	return;
}

void init_state_128(u8 *X, u8 *Z, const u8 *K, const u8 *N){
	
	//X <- K
	memcpy(X, K, KSZ);
	
	//Z <- E(K, N)
	E(Z, K, N);
	
	return;
}

void parse(u8 *out, const u8 *I, const ull len){
	
	if ( len==0 ){
		;
	} else {
		//copy content
		memcpy(out, I, len);
	}
	return;
}

void permute(u8 *Z, const u8 *Z_){
	
	//(Z'1, Z'0) <-p- Z'
	u32 p = KSZ/2;
	
	//Z0 <- Z'0 MUL alpha
	Z[0] = Z_[0]<<1;
	for(u32 j=1; j<p; j++){
		Z[j] = Z_[j]<<1 | Z_[j-1]>>7;
	}
	
	if(Z_[p-1] & 0x80){		/*10000000*/
		Z[0] ^= 0x1B;	/*00011011*/
	}
	
	//Z <- (Z'1, _)
	memcpy(&Z[p], &Z_[p], p);
	
	return;
}

void get_blk_key(u8 *Z, const u8 *Z_){
	
	//Z <- permute(Z')
	permute(Z, Z_);
	
	return;
}

void opt_pad_0s_1(u8 *pad, const u8 *tbpad, const u32 tbpadLen){
	
	if (tbpadLen == 0){ //if len == 0: return a block 0*1 
		memset(pad, 0, MSZ);
		memset(pad, 1, 1);
	} else {
		if( (tbpadLen%MSZ) == 0 ){ //if tbpad has blocklength: return tbpad
			memcpy(pad, tbpad, tbpadLen);
		} else { //else fill the remaining MSBs with 0*1
		
			//append a full block of 0s
			memset(pad, 0, MSZ);
			//set remaining bytelength+1 as 1s
			memset(pad, 1, tbpadLen+1);
			//overwrite remaining bytelength with actual content
			memcpy(pad, tbpad, tbpadLen);
		}
	}
	return;
}

void shuffle(u8 *X, const u8 *X_){
	u32 n_4 = MSZ/4;
	
	//X2 <- X'2 >>> 1
	for(u32 j=0; j<n_4; j++){
		X[n_4+j] = X_[2*n_4+((j+1)%n_4)]<<7 | X_[2*n_4+j]>>1;
	}
	
	//X <- (X'1, X'0, _, _)
	memcpy(&X[2*n_4], X_, 2*n_4);
	
	//X <- (_, _, _, X'3)
	memcpy(X, &X_[3*n_4], n_4);
		
	return;
}

void update(u8 *Y, u8 *O, const u8 *X, const u8 *I, const u32 Ilen, const u8 b){
	
	if(b == 0){
		
		//Y <- opt_pad0*1(I)
		opt_pad_0s_1(Y, I, Ilen);
		
		//Y <- X XOR opt_pad0*1(I)
		for(u32 j=0; j<MSZ; j++){
			Y[j] ^= X[j];
		}
		
	} else {
		u8 X_[MSZ] = { 0 };
		
		//X' <- shuffle(X)
		shuffle(X_, X);
		
		//O <- chop(X', |I|)
		memset(O, 0, MSZ);
		memcpy(O, X_, Ilen);
		
		//O <- chop(X', |I|) XOR I
		for(u32 j=0; j<Ilen; j++){
			O[j] ^= I[j];
		}
		
		if(b == 1){
			
			//Y <- opt_pad0*1(I)
			opt_pad_0s_1(Y, I, Ilen);
			
			//Y <- X XOR opt_pad0*1(I)
			for(u32 j=0; j<MSZ; j++){
				Y[j] ^= X[j];
			}
			
		} else if(b == 2){
			
			//Y <- opt_pad0*1(O)
			opt_pad_0s_1(Y, O, Ilen);
			
			//Y <- X XOR opt_pad0*1(O)
			for(u32 j=0; j<MSZ; j++){
				Y[j] ^= X[j];
			}
		}
	}
	return;
}

void round_function(u8 *Y, u8 *Z, u8 *O, const u8 *Y_, const u8 *Z_, const u8 *I, const u32 Ilen, const u8 b){
	
	u8 X[MSZ] = { 0 };
	
	//Z <- get_blk_key(Z')
	get_blk_key(Z, Z_);
	
	//X <- E(Z, Y')
	E(X, Z, Y_);
	
	//handling all cases of b
	update(Y, O, X, I, Ilen, b);
	
	return;
}


int comet_encrypt(
unsigned char *c,unsigned long long *clen,
const unsigned char *m,unsigned long long mlen,
const unsigned char *ad,unsigned long long adlen,
const unsigned char *nsec,
const unsigned char *npub,
const unsigned char *k
){
	*clen = mlen+CRYPTO_ABYTES;
		
	//Don't use nsec
	if(nsec != NULL){
		u32 unused_32[1];
		memcpy(unused_32, nsec, 0);
	}

	//Rounding
	//Calculate number of blocks
	ull mlen_blocks = mlen%MSZ ? ((mlen/MSZ)+1) : (mlen/MSZ);
	ull adlen_blocks = adlen%MSZ ? ((adlen/MSZ)+1) : (adlen/MSZ);
	
	
	u8 *A;
	A = (u8 *) malloc( MSZ*adlen_blocks * sizeof(u8));
		
	u8 *MSG;
	MSG = (u8 *) malloc( MSZ*mlen_blocks * sizeof(u8));
		
		
	u8 *Z;
	Z = (u8 *) malloc( KSZ*(mlen_blocks+adlen_blocks+2) * sizeof(u8));
	
	u8 *Y;
	Y = (u8 *) malloc( MSZ*(mlen_blocks+adlen_blocks+1) * sizeof(u8));
	
	u8 tag[CRYPTO_ABYTES] = { 0 };
	
	
	/*** init ***/
	
	//(Y0, Z0) <- init_state_n(K, N)
	if(MSZ == 8){
		init_state_64(Y, Z, k, npub);
	} else if(MSZ == 16){
		init_state_128(Y, Z, k, npub);
	}
	
	ull l = adlen_blocks + mlen_blocks;
	
	if(adlen != 0){
		
		/*** proc_ad ***/
		
		//(Aa-1,...,A0) <- parse(A)
		parse(A, ad, adlen);
		
		//Z0 <- Z0 XOR 00001 0^(K-5)
		Z[KSZ-1] ^= 0x08;	/*00001000*/
		
		//for i=0 to a-2 do
		for(ull i=0; i<adlen_blocks-1; i++){
			
			//(Yi+1, Zi+1) <- round(Yi, Zi, Ai, 0)
			round_function(&Y[(i+1)*MSZ], &Z[(i+1)*KSZ], NULL, &Y[i*MSZ], &Z[i*KSZ], &A[i*MSZ], MSZ, 0);
		}
		
		if(adlen%MSZ != 0){
			//Za-1 = Za-1 XOR 00010 0^(K-5)
			Z[(adlen_blocks*KSZ)-1] ^= 0x10;	/*00010000*/
		}
		round_function(&Y[adlen_blocks*MSZ], &Z[adlen_blocks*KSZ], NULL, &Y[(adlen_blocks-1)*MSZ], &Z[(adlen_blocks-1)*KSZ], &A[(adlen_blocks-1)*MSZ], adlen%MSZ ? adlen%MSZ : MSZ, 0);
	}
		
	if(mlen != 0){
		
		/*** proc_pt ***/
		
		//(Mm-1,...,M0) <- parse(M)
		parse(MSG, m, mlen);
		
		//Za <- Za XOR 00100 0^(K-5)
		Z[adlen_blocks*KSZ] ^= 0x20;	/*00100000*/
		
		//for i=0 to m-2 do
		for(ull j=0; j<mlen_blocks-1; j++){
			
			//k <- a + j
			ull x = adlen_blocks + j;
			
			//(Yk+1, Zk+1, Cj) <- round(Yk, Zk, Mj, 1)
			round_function(&Y[(x+1)*MSZ], &Z[(x+1)*KSZ], &c[j*MSZ], &Y[x*MSZ], &Z[x*KSZ], &MSG[j*MSZ], MSZ, 1);
		}
		
		if(mlen%MSZ != 0){
			//Zl-1 = Zl-1 XOR 01000 0^(K-5)
			Z[(l*KSZ)-1] ^= 0x40;	/*01000000*/
		}
		round_function(&Y[l*MSZ], &Z[l*KSZ], &c[(mlen_blocks-1)*MSZ], &Y[(l-1)*MSZ], &Z[(l-1)*KSZ], &MSG[(mlen_blocks-1)*MSZ], mlen%MSZ ? mlen%MSZ : MSZ, 1);
	}
	
	/*** proc_tg ***/
	
	//Zl = Zl XOR 10000 0^(K-5)
	Z[((l+1)*KSZ)-1] ^= 0x80;	/*10000000*/
	
	//Zl+1 <- get_blk_key(Zl)
	get_blk_key(&Z[(l+1)*KSZ], &Z[l*KSZ]);
		
	//T <- E(Zl+1, Yl)
	E(tag, &Z[(l+1)*KSZ], &Y[l*MSZ]);
	
	
	//Append Tag
	memcpy(&c[mlen], tag, CRYPTO_ABYTES);

	
	free(Y);
	free(Z);
	free(MSG);
	free(A);
	
	return 0;
}


int comet_decrypt(
unsigned char *m,unsigned long long *mlen,
unsigned char *nsec,
const unsigned char *c, unsigned long long clen,
const unsigned char *ad, unsigned long long adlen,
const unsigned char *npub,
const unsigned char *k
)
{
	*mlen = clen-CRYPTO_ABYTES;

	//Don't use nsec
	if(nsec != NULL){
		u32 unused_32[1];
		memcpy(unused_32, nsec, 0);
	}
	
	//Rounding
	//Calculate number of blocks
	ull mlen_blocks = *mlen%MSZ ? ((*mlen/MSZ)+1) : (*mlen/MSZ);
	ull adlen_blocks = adlen%MSZ ? ((adlen/MSZ)+1) : (adlen/MSZ);
	
	u8 *A;
	A = (u8 *) malloc( MSZ*adlen_blocks * sizeof(u8));
		
	u8 *C;
	C = (u8 *) malloc( MSZ*mlen_blocks * sizeof(u8));
	
	u8 *M_temp;
	M_temp = (u8 *) malloc( MSZ*mlen_blocks * sizeof(u8));
	
	
	u8 *Z;
	Z = (u8 *) malloc( KSZ*(mlen_blocks+adlen_blocks+2) * sizeof(u8));
	
	u8 *Y;
	Y = (u8 *) malloc( MSZ*(mlen_blocks+adlen_blocks+1) * sizeof(u8));
	
	u8 tag[CRYPTO_ABYTES] = { 0 };
	
	int is_auth = 0;

	
	/*** init ***/
	
	//(Y0, Z0) <- init_state_n(K, N)
	if(MSZ == 8){
		init_state_64(Y, Z, k, npub);
	} else if(MSZ == 16){
		init_state_128(Y, Z, k, npub);
	}
	
	ull l = adlen_blocks + mlen_blocks;
	
	if(adlen != 0){
		
		/*** proc_ad ***/
		
		//(Aa-1,...,A0) <- parse(A)
		parse(A, ad, adlen);
		
		//Z0 <- Z0 XOR 00001 0^(K-5)
		Z[KSZ-1] ^= 0x08;	/*00001000*/
		
		//for i=0 to a-2 do
		for(ull i=0; i<adlen_blocks-1; i++){
			
			//(Yi+1, Zi+1) <- round(Yi, Zi, Ai, 0)
			round_function(&Y[(i+1)*MSZ], &Z[(i+1)*KSZ], NULL, &Y[i*MSZ], &Z[i*KSZ], &A[i*MSZ], MSZ, 0);
		}
		
		if(adlen%MSZ != 0){
			//Za-1 = Za-1 XOR 00010 0^(K-5)
			Z[(adlen_blocks*KSZ)-1] ^= 0x10;	/*00010000*/
		}
		round_function(&Y[adlen_blocks*MSZ], &Z[adlen_blocks*KSZ], NULL, &Y[(adlen_blocks-1)*MSZ], &Z[(adlen_blocks-1)*KSZ], &A[(adlen_blocks-1)*MSZ], adlen%MSZ ? adlen%MSZ : MSZ, 0);
	}
		
	if(*mlen != 0){
		
		/*** proc_ct ***/
		
		//(Cm-1,...,C0) <- parse(C)
		parse(C, c, *mlen);
		
		//Za <- Za XOR 00100 0^(K-5)
		Z[adlen_blocks*KSZ] ^= 0x20;	/*00100000*/
		
		//for i=0 to m-2 do
		for(ull j=0; j<mlen_blocks-1; j++){
			
			//k <- a + j
			ull x = adlen_blocks + j;
			
			//(Yk+1, Zk+1, Mj) <- round(Yk, Zk, Cj, 1)
			round_function(&Y[(x+1)*MSZ], &Z[(x+1)*KSZ], &M_temp[j*MSZ], &Y[x*MSZ], &Z[x*KSZ], &C[j*MSZ], MSZ, 2);
		}
		
		if(*mlen%MSZ != 0){
			//Zl-1 = Zl-1 XOR 01000 0^(K-5)
			Z[(l*KSZ)-1] ^= 0x40;	/*01000000*/
		}
		round_function(&Y[l*MSZ], &Z[l*KSZ], &M_temp[(mlen_blocks-1)*MSZ], &Y[(l-1)*MSZ], &Z[(l-1)*KSZ], &C[(mlen_blocks-1)*MSZ], *mlen%MSZ ? *mlen%MSZ : MSZ, 2);
	}
	
	/*** proc_tg ***/
	
	//Zl = Zl XOR 10000 0^(K-5)
	Z[((l+1)*KSZ)-1] ^= 0x80;	/*10000000*/
	
	//Zl+1 <- get_blk_key(Zl)
	get_blk_key(&Z[(l+1)*KSZ], &Z[l*KSZ]);
		
	//T <- E(Zl+1, Yl)
	E(tag, &Z[(l+1)*KSZ], &Y[l*MSZ]);
	
	
	//compare T' == T (0 for equal)
	if( memcmp(tag, &c[*mlen], CRYPTO_ABYTES) == 0 ){
	
		//only copy message if auth succeeded
		//M = (Mm-1,...,M0)
		memcpy(m, M_temp, *mlen);
	
		//if T' == T -> is_auth = 1	
		is_auth = 1;
	
	} else {
		
		//if T' =/= T -> is_auth = 0
		is_auth = 0;
		
	}
	
	free(Y);
	free(Z);
	free(M_temp);
	free(C);
	free(A);
	
	if(is_auth){
		return 0;
	} else {
		return -1;
	}
}