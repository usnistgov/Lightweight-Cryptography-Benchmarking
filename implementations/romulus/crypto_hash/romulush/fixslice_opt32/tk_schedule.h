#ifndef TK_SCHEDULE_H_
#define TK_SCHEDULE_H_

typedef unsigned char u8;
typedef unsigned int u32;

void packing(u32* out, const u8* in);
void unpacking(u8* out, u32 *in);
void precompute_rtk2_3(u32* rtk, const u8* tk2, const u8* tk3);
void precompute_rtk1(u32* rtk1, const u8* tk1);

#define ROR(x,y) (((x) >> (y)) | ((x) << (32 - (y))))

#define XOR_BLOCKS(x,y) ({ 			\
	(x)[0] ^= (y)[0];				\
	(x)[1] ^= (y)[1];				\
	(x)[2] ^= (y)[2];				\
	(x)[3] ^= (y)[3];				\
})
	
#define SWAPMOVE(a, b, mask, n)	({	\
	tmp = (b ^ (a >> n)) & mask;	\
	b ^= tmp;						\
	a ^= (tmp << n);				\
})

#define LE_LOAD(x, y) 				\
	*(x) = (((u32)(y)[3] << 24) | 	\
		((u32)(y)[2] << 16) 	| 	\
		((u32)(y)[1] << 8) 		| 	\
		(y)[0]);

#define LE_STORE(x, y)				\
	(x)[0] = (y) & 0xff; 			\
	(x)[1] = ((y) >> 8) & 0xff; 	\
	(x)[2] = ((y) >> 16) & 0xff; 	\
	(x)[3] = (y) >> 24;

#endif  // TK_SCHEDULE_H_