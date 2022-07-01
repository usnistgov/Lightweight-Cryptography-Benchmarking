#ifndef TK_SCHEDULE_H_
#define TK_SCHEDULE_H_

#include <stdint.h>
#include "skinny128.h"

#define TWEAKEYBYTES 	16
#define TKPERMORDER 	16

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

#define LE_LOAD(x, y) 					\
	*(x) = (((uint32_t)(y)[3] << 24) | 	\
			((uint32_t)(y)[2] << 16) | 	\
			((uint32_t)(y)[1] << 8)  | 	\
			(y)[0]);

#define LE_STORE(x, y)				\
	(x)[0] = (y) & 0xff; 			\
	(x)[1] = ((y) >> 8) & 0xff; 	\
	(x)[2] = ((y) >> 16) & 0xff; 	\
	(x)[3] = (y) >> 24;

void packing(uint32_t* out, const uint8_t* in);
void unpacking(uint8_t* out, uint32_t *in);
void tk_schedule_1(uint32_t *rtk_1, const uint8_t *tk_1);
void tk_schedule_13(uint32_t *rtk_1, uint32_t *rtk_3,
    const uint8_t *tk_1,
    const uint8_t *tk_3);
void tk_schedule_23(uint32_t *rtk_23,
    const uint8_t *tk_2,
    const uint8_t *tk_3);
void tk_schedule_123(uint32_t *rtk_1, uint32_t *rtk_23,
    const uint8_t *tk_1,
    const uint8_t *tk_2,
    const uint8_t *tk_3);

#endif  // TK_SCHEDULE_H_
