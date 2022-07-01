#ifndef SKINNY128_H_
#define SKINNY128_H_

typedef unsigned char u8;
typedef unsigned int u32;

void skinny128_384_plus(u8* ctext, const u8* ptext, const u32* rtk1, const u32* rtk2_3);

#define SKINNY128_384_ROUNDS	40

#define QUADRUPLE_ROUND(state, rtk1, rtk2_3) ({			\
	state[3] ^= ~(state[0] | state[1]);					\
	SWAPMOVE(state[2], state[1], 0x55555555, 1);		\
	SWAPMOVE(state[3], state[2], 0x55555555, 1);		\
	state[1] ^= ~(state[2] | state[3]);					\
	SWAPMOVE(state[1], state[0], 0x55555555, 1);		\
	SWAPMOVE(state[0], state[3], 0x55555555, 1);		\
	state[3] ^= ~(state[0] | state[1]);					\
	SWAPMOVE(state[2], state[1], 0x55555555, 1);		\
	SWAPMOVE(state[3], state[2], 0x55555555, 1);		\
	state[1] ^= (state[2] | state[3]);					\
	SWAPMOVE(state[3], state[0], 0x55555555, 0);		\
	state[0] ^= (rtk1)[0];								\
	state[1] ^= (rtk1)[1];								\
	state[2] ^= (rtk1)[2];								\
	state[3] ^= (rtk1)[3];								\
	state[0] ^= (rtk2_3)[0];							\
	state[1] ^= (rtk2_3)[1];							\
	state[2] ^= (rtk2_3)[2];							\
	state[3] ^= (rtk2_3)[3];							\
	mixcolumns_0(state);								\
	state[1] ^= ~(state[2] | state[3]); 				\
	SWAPMOVE(state[1], state[0], 0x55555555, 1);		\
	SWAPMOVE(state[0], state[3], 0x55555555, 1);		\
	state[3] ^= ~(state[0] | state[1]);					\
	SWAPMOVE(state[2], state[1], 0x55555555, 1);		\
	SWAPMOVE(state[3], state[2], 0x55555555, 1);		\
	state[1] ^= ~(state[2] | state[3]);					\
	SWAPMOVE(state[1], state[0], 0x55555555, 1);		\
	SWAPMOVE(state[0], state[3], 0x55555555, 1);		\
	state[3] ^= (state[0] | state[1]);					\
	SWAPMOVE(state[1], state[2], 0x55555555, 0);		\
	state[0] ^= (rtk1)[4];								\
	state[1] ^= (rtk1)[5];								\
	state[2] ^= (rtk1)[6];								\
	state[3] ^= (rtk1)[7];								\
	state[0] ^= (rtk2_3)[4];							\
	state[1] ^= (rtk2_3)[5];							\
	state[2] ^= (rtk2_3)[6];							\
	state[3] ^= (rtk2_3)[7];							\
	mixcolumns_1(state);								\
	state[3] ^= ~(state[0] | state[1]);					\
	SWAPMOVE(state[2], state[1], 0x55555555, 1);		\
	SWAPMOVE(state[3], state[2], 0x55555555, 1);		\
	state[1] ^= ~(state[2] | state[3]);					\
	SWAPMOVE(state[1], state[0], 0x55555555, 1);		\
	SWAPMOVE(state[0], state[3], 0x55555555, 1);		\
	state[3] ^= ~(state[0] | state[1]);					\
	SWAPMOVE(state[2], state[1], 0x55555555, 1);		\
	SWAPMOVE(state[3], state[2], 0x55555555, 1);		\
	state[1] ^= (state[2] | state[3]);					\
	SWAPMOVE(state[3], state[0], 0x55555555, 0);		\
	state[0] ^= (rtk1)[8];								\
	state[1] ^= (rtk1)[9];								\
	state[2] ^= (rtk1)[10];								\
	state[3] ^= (rtk1)[11];								\
	state[0] ^= (rtk2_3)[8];							\
	state[1] ^= (rtk2_3)[9];							\
	state[2] ^= (rtk2_3)[10];							\
	state[3] ^= (rtk2_3)[11];							\
	mixcolumns_2(state);								\
	state[1] ^= ~(state[2] | state[3]); 				\
	SWAPMOVE(state[1], state[0], 0x55555555, 1);		\
	SWAPMOVE(state[0], state[3], 0x55555555, 1);		\
	state[3] ^= ~(state[0] | state[1]);					\
	SWAPMOVE(state[2], state[1], 0x55555555, 1);		\
	SWAPMOVE(state[3], state[2], 0x55555555, 1);		\
	state[1] ^= ~(state[2] | state[3]);					\
	SWAPMOVE(state[1], state[0], 0x55555555, 1);		\
	SWAPMOVE(state[0], state[3], 0x55555555, 1);		\
	state[3] ^= (state[0] | state[1]);					\
	SWAPMOVE(state[1], state[2], 0x55555555, 0);		\
	state[0] ^= (rtk1)[12];								\
	state[1] ^= (rtk1)[13];								\
	state[2] ^= (rtk1)[14];								\
	state[3] ^= (rtk1)[15];								\
	state[0] ^= (rtk2_3)[12];							\
	state[1] ^= (rtk2_3)[13];							\
	state[2] ^= (rtk2_3)[14];							\
	state[3] ^= (rtk2_3)[15];							\
	mixcolumns_3(state);								\
})


#endif  // SKINNY128_H_