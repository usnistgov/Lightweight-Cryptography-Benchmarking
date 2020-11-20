#ifndef SKINNY128_H_
#define SKINNY128_H_

typedef unsigned char u8;
typedef unsigned int u32;

#define SKINNY128_384_ROUNDS	56

extern void skinny128_384(u8* ctext, u8* ctext_bis, const u8* ptext, const u8* ptext_bis, const u32* rtk1, const u32* rtk2_3);
extern void skinny128_384_inv(u8* ptext, u8* ptext_bis, const u8* ctext, const u8* ctext_bis, const u32* rtk1, const u32* rtk2_3);
extern void tkschedule_lfsr_2(u32* rtk, const u8* tk2, const u8* tk2_bis, const int rounds);
extern void pack_tk1(u32* rtk, const u8* tk2, const u8* tk2_bis, const int rounds);
extern void tkschedule_lfsr_3(u32* rtk, const u8* tk3, const u8* tk3_bis, const int rounds);
extern void tkschedule_perm(u32* rtk);
extern void tkschedule_perm_tk1(u32* rtk1, const u8* tk1, const u8* tk1_bis);

#endif  // SKINNY128_H_