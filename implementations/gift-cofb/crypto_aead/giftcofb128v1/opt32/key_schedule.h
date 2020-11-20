#ifndef KEYSCHEDULE_H_
#define KEYSCHEDULE_H_

#define REARRANGE_RKEY_0(x) ({			\
	SWAPMOVE(x, x, 0x00550055, 9);		\
	SWAPMOVE(x, x, 0x000f000f, 12);		\
	SWAPMOVE(x, x, 0x00003333, 18);		\
	SWAPMOVE(x, x, 0x000000ff, 24);		\
})

#define REARRANGE_RKEY_1(x) ({			\
	SWAPMOVE(x, x, 0x11111111, 3);		\
	SWAPMOVE(x, x, 0x03030303, 6);		\
	SWAPMOVE(x, x, 0x000f000f, 12);		\
	SWAPMOVE(x, x, 0x000000ff, 24);		\
})

#define REARRANGE_RKEY_2(x) ({			\
	SWAPMOVE(x, x, 0x0000aaaa, 15);		\
	SWAPMOVE(x, x, 0x00003333, 18);		\
	SWAPMOVE(x, x, 0x0000f0f0, 12);		\
	SWAPMOVE(x, x, 0x000000ff, 24);		\
})

#define REARRANGE_RKEY_3(x) ({			\
	SWAPMOVE(x, x, 0x0a0a0a0a, 3);		\
	SWAPMOVE(x, x, 0x00cc00cc, 6);		\
	SWAPMOVE(x, x, 0x0000f0f0, 12);		\
	SWAPMOVE(x, x, 0x000000ff, 24);		\
})

#define KEY_UPDATE(x)											\
	(((x) >> 12) & 0x0000000f)	| (((x) & 0x00000fff) << 4) | 	\
	(((x) >> 2) & 0x3fff0000)	| (((x) & 0x00030000) << 14)

#define KEY_TRIPLE_UPDATE_0(x)									\
	(ROR((x) & 0x33333333, 24) 	| ROR((x) & 0xcccccccc, 16))

#define KEY_DOUBLE_UPDATE_1(x)									\
	((((x) >> 4) & 0x0f000f00)	| (((x) & 0x0f000f00) << 4) | 	\
	(((x) >> 6) & 0x00030003)	| (((x) & 0x003f003f) << 2))

#define KEY_TRIPLE_UPDATE_1(x)									\
	((((x) >> 6) & 0x03000300)	| (((x) & 0x3f003f00) << 2) | 	\
	(((x) >> 5) & 0x00070007)	| (((x) & 0x001f001f) << 3))

#define KEY_DOUBLE_UPDATE_2(x)									\
	(ROR((x) & 0xaaaaaaaa, 24)	| ROR((x) & 0x55555555, 16))

#define KEY_TRIPLE_UPDATE_2(x)									\
	(ROR((x) & 0x55555555, 24)	| ROR((x) & 0xaaaaaaaa, 20))

#define KEY_DOUBLE_UPDATE_3(x)									\
	((((x) >> 2) & 0x03030303)	| (((x) & 0x03030303) << 2) | 	\
	(((x) >> 1) & 0x70707070)	| (((x) & 0x10101010) << 3))

#define KEY_TRIPLE_UPDATE_3(x)									\
	((((x) >> 18) & 0x00003030)	| (((x) & 0x01010101) << 3) | 	\
	(((x) >> 14) & 0x0000c0c0)	| (((x) & 0x0000e0e0) << 15)|	\
	(((x) >> 1) & 0x07070707)	| (((x) & 0x00001010) << 19))

#define KEY_DOUBLE_UPDATE_4(x)									\
	((((x) >> 4)  & 0x0fff0000)	| (((x) & 0x000f0000) << 12) | 	\
	(((x) >> 8)  & 0x000000ff)	| (((x) & 0x000000ff) << 8))

#define KEY_TRIPLE_UPDATE_4(x)									\
	((((x) >> 6)  & 0x03ff0000)	| (((x) & 0x003f0000) << 10) |	\
	(((x) >> 4)  & 0x00000fff)	| (((x) & 0x0000000f) << 12))

#endif  // KEYSCHEDULE_H_