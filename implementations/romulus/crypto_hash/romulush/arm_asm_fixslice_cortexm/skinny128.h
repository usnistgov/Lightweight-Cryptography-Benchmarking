#ifndef SKINNY128_H_
#define SKINNY128_H_

typedef unsigned char u8;
typedef unsigned int u32;

#define SKINNY128_384_ROUNDS	40

extern void skinny128_384(u8* ctext, const u32* rtk2_3, const u8* ptext, const u32* rtk1);
extern void skinny128_384_inv(u8* ptext, const u32* rtk2_3, const u8* ctext, const u32* rtk1);
extern void tkschedule_lfsr(u32* rtk2_3, const u8* tk2, const u8* tk3, const int rounds);
extern void tkschedule_perm(u32* rtk2_3);
extern void tkschedule_perm_tk1(u32* rtk1, const u8* tk1);


#endif  // SKINNY128_H_