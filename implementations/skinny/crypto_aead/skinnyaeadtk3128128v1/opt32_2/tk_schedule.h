#ifndef TK_SCHEDULE_BS_H_
#define TK_SCHEDULE_BS_H_

#include <stdint.h>

typedef uint8_t 	u8;
typedef uint32_t 	u32;

typedef struct {
	u32 rtk1[8*16];
	u32 rtk2_3[8*56];
} tweakey;
	
void packing(u32* out, const u8* block0, const u8* block1);
void unpacking(u8* out, u8* out_bis, u32 *in);
void precompute_rtk2_3(u32* rtk, const u8* tk2, const u8* tk3, int rounds);
void precompute_rtk1(u32* rtk1, const u8* tk1, const u8* tk1_bis);

#define LFSR2(tk) ({				\
	tmp = (tk)[0] ^ (tk)[2];		\
	(tk)[0] = (tk)[1]; 				\
	(tk)[1] = (tk)[2];				\
	(tk)[2] = (tk)[3];				\
	(tk)[3] = (tk)[4];				\
	(tk)[4] = (tk)[5];				\
	(tk)[5] = (tk)[6];				\
	(tk)[6] = (tk)[7];				\
	(tk)[7] = tmp;					\
})

#define LFSR3(tk) ({				\
	tmp = (tk)[7] ^ (tk)[1]; 		\
	(tk)[7] = (tk)[6];				\
	(tk)[6] = (tk)[5];				\
	(tk)[5] = (tk)[4];				\
	(tk)[4] = (tk)[3];				\
	(tk)[3] = (tk)[2];				\
	(tk)[2] = (tk)[1];				\
	(tk)[1] = (tk)[0];				\
	(tk)[0] = tmp;					\
})

#define XOR_BLOCK(x,y) ({ 			\
	(x)[0] ^= (y)[0];				\
	(x)[1] ^= (y)[1];				\
	(x)[2] ^= (y)[2];				\
	(x)[3] ^= (y)[3];				\
	(x)[4] ^= (y)[4];				\
	(x)[5] ^= (y)[5];				\
	(x)[6] ^= (y)[6];				\
	(x)[7] ^= (y)[7];				\
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

#define ROR(x,y) (((x) >> (y)) | ((x) << (32 - (y))))

#endif  // TK_SCHEDULE_BS_H_