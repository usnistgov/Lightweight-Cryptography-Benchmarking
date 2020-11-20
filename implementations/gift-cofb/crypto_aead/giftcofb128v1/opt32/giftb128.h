#ifndef GIFT128_H_
#define GIFT128_H_

typedef unsigned char u8;
typedef unsigned int u32;

extern void precompute_rkeys(u32* rkeys, const u8* key);
extern void giftb128(u8* out, const u8* in, const u32* rkeys);

#define ROR(x,y)											\
	(((x) >> (y)) | ((x) << (32 - (y))))
#define BYTE_ROR_2(x)										\
	((((x) >> 2) & 0x3f3f3f3f)	| (((x) & 0x03030303) << 6))
#define BYTE_ROR_4(x) 										\
	((((x) >> 4) & 0x0f0f0f0f)	| (((x) & 0x0f0f0f0f) << 4))
#define BYTE_ROR_6(x) 										\
	((((x) >> 6) & 0x03030303)	| (((x) & 0x3f3f3f3f) << 2))
#define HALF_ROR_4(x) 										\
	((((x) >> 4) & 0x0fff0fff)	| (((x) & 0x000f000f) << 12))
#define HALF_ROR_8(x) 										\
	((((x) >> 8) & 0x00ff00ff)	| (((x) & 0x00ff00ff) << 8))
#define HALF_ROR_12(x) 										\
	((((x) >> 12)& 0x000f000f)	| (((x) & 0x0fff0fff) << 4))
#define NIBBLE_ROR_1(x)										\
	((((x) >> 1) & 0x77777777) 	| (((x) & 0x11111111) << 3))
#define NIBBLE_ROR_2(x)										\
	((((x) >> 2) & 0x33333333) 	| (((x) & 0x33333333) << 2))
#define NIBBLE_ROR_3(x)										\
	((((x) >> 3) & 0x11111111) 	| (((x) & 0x77777777) << 1))

#define SWAPMOVE(a, b, mask, n)								\
	tmp = (b ^ (a >> n)) & mask;							\
	b ^= tmp;												\
	a ^= (tmp << n);

#define SBOX(s0, s1, s2, s3)								\
	s1 ^= s0 & s2;											\
	s0 ^= s1 & s3;											\
	s2 ^= s0 | s1;											\
	s3 ^= s2;												\
	s1 ^= s3;												\
	s3 ^= 0xffffffff;										\
	s2 ^= s0 & s1;

#define QUINTUPLE_ROUND(state, rkey, rconst) ({				\
	SBOX(state[0], state[1], state[2], state[3]);			\
	state[3] = NIBBLE_ROR_1(state[3]);						\
	state[1] = NIBBLE_ROR_2(state[1]);						\
	state[2] = NIBBLE_ROR_3(state[2]);						\
	state[1] ^= (rkey)[0];									\
	state[2] ^= (rkey)[1];									\
	state[0] ^= (rconst)[0];								\
	SBOX(state[3], state[1], state[2], state[0]);			\
	state[0] = HALF_ROR_4(state[0]);						\
	state[1] = HALF_ROR_8(state[1]);						\
	state[2] = HALF_ROR_12(state[2]);						\
	state[1] ^= (rkey)[2];									\
	state[2] ^= (rkey)[3];									\
	state[3] ^= (rconst)[1];								\
	SBOX(state[0], state[1], state[2], state[3]);			\
	state[3] = ROR(state[3], 16);							\
	state[2] = ROR(state[2], 16);							\
	SWAPMOVE(state[1], state[1], 0x55555555, 1);			\
	SWAPMOVE(state[2], state[2], 0x00005555, 1);			\
	SWAPMOVE(state[3], state[3], 0x55550000, 1);			\
	state[1] ^= (rkey)[4];									\
	state[2] ^= (rkey)[5];									\
	state[0] ^= (rconst)[2];								\
	SBOX(state[3], state[1], state[2], state[0]);			\
	state[0] = BYTE_ROR_6(state[0]);						\
	state[1] = BYTE_ROR_4(state[1]);						\
	state[2] = BYTE_ROR_2(state[2]);						\
	state[1] ^= (rkey)[6];									\
	state[2] ^= (rkey)[7];									\
	state[3] ^= (rconst)[3];								\
	SBOX(state[0], state[1], state[2], state[3]);			\
	state[3] = ROR(state[3], 24);							\
	state[1] = ROR(state[1], 16);							\
	state[2] = ROR(state[2], 8);							\
	state[1] ^= (rkey)[8];									\
	state[2] ^= (rkey)[9];									\
	state[0] ^= (rconst)[4];								\
	state[0] ^= state[3];									\
	state[3] ^= state[0];									\
	state[0] ^= state[3];									\
})

#endif  // GIFT128_H_