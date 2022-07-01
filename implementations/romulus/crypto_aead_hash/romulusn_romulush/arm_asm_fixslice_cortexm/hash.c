#include "skinny128.h"
#include "romulus.h"
#include <string.h>
#include <stdlib.h>

void hirose_128_128_256
	(unsigned char* h,
	 unsigned char* g,
	 const unsigned char* m) {

	int i;
	u8 hh[16];
    u32 rtk1[4*16];
    u32 rtk2_3[4*SKINNY128_384_ROUNDS];

    // precompute the round tweakeys
    tkschedule_perm_tk1(rtk1, g);
    tkschedule_lfsr(rtk2_3, m, m+16, SKINNY128_384_ROUNDS);
    tkschedule_perm(rtk2_3);
	
	// assign the key for the hirose compression function
	for (i = 0; i < 16; i++) {
		g[i]   = h[i];
		hh[i]  = h[i];
	}
	g[0] ^= 0x01;

	// run skinny-128-384+
    skinny128_384(h, rtk2_3, h, rtk1);
    skinny128_384(g, rtk2_3, g, rtk1);

	for (i = 0; i < 16; i++) {
		h[i] ^= hh[i];
		g[i] ^= hh[i];
	}
	g[0] ^= 0x01;
}

void initialize
	(unsigned char* h,
	 unsigned char* g) {

 	u8 i;
	for (i = 0; i < 16; i++) {
		h[i] = 0;
		g[i] = 0;
	}
}

void pad(const unsigned char* m, unsigned char* mp, int l, int len8) {
	int i;
	for (i = 0; i < l; i++) {
		if (i < len8)
			mp[i] = m[i];
		else if (i == l - 1)
      		mp[i] = (len8 & 0x1f);
		else
			mp[i] = 0x00;
	}
}

int crypto_hash
	(unsigned char *out,
	 const unsigned char *in,
	 unsigned long long inlen) {

	u8 h[16];
	u8 g[16];
	u8 p[32];
	u8 i;

	initialize(h,g);

	while (inlen >= 32) { // Normal loop
		hirose_128_128_256(h,g,in);
		in += 32;
		inlen -= 32;
	}

	pad(in,p,32,inlen);
	h[0] ^= 0x02;
	hirose_128_128_256(h,g,p);
	
	for (i = 0; i < 16; i++) { // Assign the output tag
		out[i] = h[i];
		out[i+16] = g[i];
	}
	
	return 0;
}
