/* ======================================================================== */
/*
 * Saturnin block cipher implementation (reference code, not optimized).
 */

#include <string.h>
#include <stdint.h>

/*
 * Compute round constants for R super-rounds and domain D.
 * Assumptions:
 *   0 <= R <= 31
 *   0 <= D <= 15
 */
static void
make_round_constants(int R, int D, uint16_t *RC0, uint16_t *RC1)
{
	uint16_t x0, x1;
	int n;

	x0 = x1 = D + (R << 4) + 0xFE00;

	for (n = 0; n < R; n ++) {
		int i;

		for (i = 0; i < 16; i ++) {
			x0 = (x0 << 1) ^ (0x2D & -(x0 >> 15));
			x1 = (x1 << 1) ^ (0x53 & -(x1 >> 15));
		}
		RC0[n] = x0;
		RC1[n] = x1;
	}
}

/*
 * Apply the S-boxes on the state (sigma_0 and sigma_1).
 */
static void
S_box(uint16_t *state)
{
	int i;

	for (i = 0; i < 16; i += 8) {
		uint16_t a, b, c, d;

		/* sigma_0 */
		a = state[i + 0];
		b = state[i + 1];
		c = state[i + 2];
		d = state[i + 3];
		a ^= b & c;
		b ^= a | d;
		d ^= b | c;
		c ^= b & d;
		b ^= a | c;
		a ^= b | d;
		state[i + 0] = b;
		state[i + 1] = c;
		state[i + 2] = d;
		state[i + 3] = a;

		/* sigma_1 */
		a = state[i + 4];
		b = state[i + 5];
		c = state[i + 6];
		d = state[i + 7];
		a ^= b & c;
		b ^= a | d;
		d ^= b | c;
		c ^= b & d;
		b ^= a | c;
		a ^= b | d;
		state[i + 4] = d;
		state[i + 5] = b;
		state[i + 6] = a;
		state[i + 7] = c;
	}
}

/*
 * Apply the inverse S-boxes on the state (inv_sigma_0 and inv_sigma_1).
 */
static void
S_box_inv(uint16_t *state)
{
	int i;

	for (i = 0; i < 16; i += 8) {
		uint16_t a, b, c, d;

		/* inv_sigma_0 */
		b = state[i + 0];
		c = state[i + 1];
		d = state[i + 2];
		a = state[i + 3];
		a ^= b | d;
		b ^= a | c;
		c ^= b & d;
		d ^= b | c;
		b ^= a | d;
		a ^= b & c;
		state[i + 0] = a;
		state[i + 1] = b;
		state[i + 2] = c;
		state[i + 3] = d;

		/* inv_sigma_1 */
		d = state[i + 4];
		b = state[i + 5];
		a = state[i + 6];
		c = state[i + 7];
		a ^= b | d;
		b ^= a | c;
		c ^= b & d;
		d ^= b | c;
		b ^= a | d;
		a ^= b & c;
		state[i + 4] = a;
		state[i + 5] = b;
		state[i + 6] = c;
		state[i + 7] = d;
	}
}

/*
 * Apply the linear transform (MDS) on the state.
 */
static void
MDS(uint16_t *state)
{
	uint16_t x0, x1, x2, x3, x4, x5, x6, x7;
	uint16_t x8, x9, xa, xb, xc, xd, xe, xf;

	x0 = state[0x0];
	x1 = state[0x1];
	x2 = state[0x2];
	x3 = state[0x3];
	x4 = state[0x4];
	x5 = state[0x5];
	x6 = state[0x6];
	x7 = state[0x7];
	x8 = state[0x8];
	x9 = state[0x9];
	xa = state[0xa];
	xb = state[0xb];
	xc = state[0xc];
	xd = state[0xd];
	xe = state[0xe];
	xf = state[0xf];

#define MUL(t0, t1, t2, t3)   do { \
		uint16_t mul_tmp = (t0); \
		(t0) = (t1); \
		(t1) = (t2); \
		(t2) = (t3); \
		(t3) = mul_tmp ^ (t0); \
	} while (0)

	x8 ^= xc; x9 ^= xd; xa ^= xe; xb ^= xf; /* C ^= D */
	x0 ^= x4; x1 ^= x5; x2 ^= x6; x3 ^= x7; /* A ^= B */
	MUL(x4, x5, x6, x7);                    /* B = MUL(B) */
	MUL(xc, xd, xe, xf);                    /* D = MUL(D) */
	x4 ^= x8; x5 ^= x9; x6 ^= xa; x7 ^= xb; /* B ^= C */
	xc ^= x0; xd ^= x1; xe ^= x2; xf ^= x3; /* D ^= A */
	MUL(x0, x1, x2, x3);                    /* A = MUL(A) */
	MUL(x0, x1, x2, x3);                    /* A = MUL(A) */
	MUL(x8, x9, xa, xb);                    /* C = MUL(C) */
	MUL(x8, x9, xa, xb);                    /* C = MUL(C) */
	x8 ^= xc; x9 ^= xd; xa ^= xe; xb ^= xf; /* C ^= D */
	x0 ^= x4; x1 ^= x5; x2 ^= x6; x3 ^= x7; /* A ^= B */
	x4 ^= x8; x5 ^= x9; x6 ^= xa; x7 ^= xb; /* B ^= C */
	xc ^= x0; xd ^= x1; xe ^= x2; xf ^= x3; /* D ^= A */

#undef MUL

	state[0x0] = x0;
	state[0x1] = x1;
	state[0x2] = x2;
	state[0x3] = x3;
	state[0x4] = x4;
	state[0x5] = x5;
	state[0x6] = x6;
	state[0x7] = x7;
	state[0x8] = x8;
	state[0x9] = x9;
	state[0xa] = xa;
	state[0xb] = xb;
	state[0xc] = xc;
	state[0xd] = xd;
	state[0xe] = xe;
	state[0xf] = xf;
}

/*
 * Apply the inverse of the linear transform (MDS) on the state.
 */
static void
MDS_inv(uint16_t *state)
{
	uint16_t x0, x1, x2, x3, x4, x5, x6, x7;
	uint16_t x8, x9, xa, xb, xc, xd, xe, xf;

	x0 = state[0x0];
	x1 = state[0x1];
	x2 = state[0x2];
	x3 = state[0x3];
	x4 = state[0x4];
	x5 = state[0x5];
	x6 = state[0x6];
	x7 = state[0x7];
	x8 = state[0x8];
	x9 = state[0x9];
	xa = state[0xa];
	xb = state[0xb];
	xc = state[0xc];
	xd = state[0xd];
	xe = state[0xe];
	xf = state[0xf];

#define MULinv(t0, t1, t2, t3)   do { \
		uint16_t mul_tmp = (t3); \
		(t3) = (t2); \
		(t2) = (t1); \
		(t1) = (t0); \
		(t0) = mul_tmp ^ (t1); \
	} while (0)

	x4 ^= x8; x5 ^= x9; x6 ^= xa; x7 ^= xb; /* B ^= C */
	xc ^= x0; xd ^= x1; xe ^= x2; xf ^= x3; /* D ^= A */
	x8 ^= xc; x9 ^= xd; xa ^= xe; xb ^= xf; /* C ^= D */
	x0 ^= x4; x1 ^= x5; x2 ^= x6; x3 ^= x7; /* A ^= B */
	MULinv(x0, x1, x2, x3);                 /* A = MULinv(A) */
	MULinv(x0, x1, x2, x3);                 /* A = MULinv(A) */
	MULinv(x8, x9, xa, xb);                 /* C = MULinv(C) */
	MULinv(x8, x9, xa, xb);                 /* C = MULinv(C) */
	x4 ^= x8; x5 ^= x9; x6 ^= xa; x7 ^= xb; /* B ^= C */
	xc ^= x0; xd ^= x1; xe ^= x2; xf ^= x3; /* D ^= A */
	MULinv(x4, x5, x6, x7);                 /* B = MULinv(B) */
	MULinv(xc, xd, xe, xf);                 /* D = MULinv(D) */
	x8 ^= xc; x9 ^= xd; xa ^= xe; xb ^= xf; /* C ^= D */
	x0 ^= x4; x1 ^= x5; x2 ^= x6; x3 ^= x7; /* A ^= B */

#undef MULinv

	state[0x0] = x0;
	state[0x1] = x1;
	state[0x2] = x2;
	state[0x3] = x3;
	state[0x4] = x4;
	state[0x5] = x5;
	state[0x6] = x6;
	state[0x7] = x7;
	state[0x8] = x8;
	state[0x9] = x9;
	state[0xa] = xa;
	state[0xb] = xb;
	state[0xc] = xc;
	state[0xd] = xd;
	state[0xe] = xe;
	state[0xf] = xf;
}

/*
 * Apply the SR_slice permutation.
 */
static void
SR_slice(uint16_t *state)
{
	int i;

	for (i = 0; i < 4; i ++) {
		state[ 4 + i] = ((state[ 4 + i] & 0x7777) << 1)
			| ((state[ 4 + i] & 0x8888) >> 3);
		state[ 8 + i] = ((state[ 8 + i] & 0x3333) << 2)
			| ((state[ 8 + i] & 0xcccc) >> 2);
		state[12 + i] = ((state[12 + i] & 0x1111) << 3)
			| ((state[12 + i] & 0xeeee) >> 1);
	}
}

/*
 * Apply the inverse of the SR_slice permutation.
 */
static void
SR_slice_inv(uint16_t *state)
{
	int i;

	for (i = 0; i < 4; i ++) {
		state[ 4 + i] = ((state[ 4 + i] & 0x1111) << 3)
			| ((state[ 4 + i] & 0xeeee) >> 1);
		state[ 8 + i] = ((state[ 8 + i] & 0x3333) << 2)
			| ((state[ 8 + i] & 0xcccc) >> 2);
		state[12 + i] = ((state[12 + i] & 0x7777) << 1)
			| ((state[12 + i] & 0x8888) >> 3);
	}
}

/*
 * Apply the SR_sheet permutation.
 */
static void
SR_sheet(uint16_t *state)
{
	int i;

	for (i = 0; i < 4; i ++) {
		state[ 4 + i] = ((state[ 4 + i] <<  4) | (state[ 4 + i] >> 12));
		state[ 8 + i] = ((state[ 8 + i] <<  8) | (state[ 8 + i] >>  8));
		state[12 + i] = ((state[12 + i] << 12) | (state[12 + i] >>  4));
	}
}

/*
 * Apply the inverse of the SR_sheet permutation.
 */
static void
SR_sheet_inv(uint16_t *state)
{
	int i;

	for (i = 0; i < 4; i ++) {
		state[ 4 + i] = ((state[ 4 + i] << 12) | (state[ 4 + i] >>  4));
		state[ 8 + i] = ((state[ 8 + i] <<  8) | (state[ 8 + i] >>  8));
		state[12 + i] = ((state[12 + i] <<  4) | (state[12 + i] >> 12));
	}
}

/*
 * XOR the key into the state.
 */
static void
XOR_key(const uint16_t *key, uint16_t *state)
{
	int i;

	for (i = 0; i < 16; i ++) {
		state[i] ^= key[i];
	}
}

/*
 * XOR the rotated key into the state.
 */
static void
XOR_key_rotated(const uint16_t *key, uint16_t *state)
{
	int i;

	for (i = 0; i < 16; i ++) {
		state[i] ^= (key[i] << 11) | (key[i] >> 5);
	}
}

/*
 * Perform one Saturnin block encryption.
 *   R     number of super-rounds (0 to 31)
 *   D     separation domain (0 to 15)
 *   key   key (32 bytes)
 *   buf   block to encrypt
 * The 'key' and 'buf' buffers may overlap. The encrypted block is
 * written back in 'buf'.
 */
void
saturnin_block_encrypt(int R, int D, const uint8_t *key, uint8_t *buf)
{
	uint16_t RC0[31], RC1[31];
	uint16_t xk[16], xb[16];
	int i;

	/*
	 * Decode key and input block.
	 */
	for (i = 0; i < 16; i ++) {
		xk[i] = key[i << 1] + ((uint16_t)key[(i << 1) + 1] << 8);
		xb[i] = buf[i << 1] + ((uint16_t)buf[(i << 1) + 1] << 8);
	}

	/*
	 * Compute round constants.
	 */
	make_round_constants(R, D, RC0, RC1);

	/*
	 * XOR key into state.
	 */
	XOR_key(xk, xb);

	/*
	 * Run all rounds (two rounds per super-round).
	 */
	for (i = 0; i < R; i ++) {
		/*
		 * Even round.
		 */
		S_box(xb);
		MDS(xb);

		/*
		 * Odd round.
		 */
		S_box(xb);
		if ((i & 1) == 0) {
			/*
			 * Round r = 1 mod 4.
			 */
			SR_slice(xb);
			MDS(xb);
			SR_slice_inv(xb);
			xb[0] ^= RC0[i];
			xb[8] ^= RC1[i];
			XOR_key_rotated(xk, xb);
		} else {
			/*
			 * Round r = 3 mod 4.
			 */
			SR_sheet(xb);
			MDS(xb);
			SR_sheet_inv(xb);
			xb[0] ^= RC0[i];
			xb[8] ^= RC1[i];
			XOR_key(xk, xb);
		}
	}

	/*
	 * Encode output block.
	 */
	for (i = 0; i < 16; i ++) {
		buf[(i << 1) + 0] = (uint8_t)xb[i];
		buf[(i << 1) + 1] = (uint8_t)(xb[i] >> 8);
	}
}

/*
 * Perform one Saturnin block decryption.
 *   R     number of super-rounds (0 to 31)
 *   D     separation domain (0 to 15)
 *   key   key (32 bytes)
 *   buf   block to decrypt
 * The 'key' and 'buf' buffers may overlap. The decrypted block is
 * written back in 'buf'.
 */
void
saturnin_block_decrypt(int R, int D, const uint8_t *key, uint8_t *buf)
{
	uint16_t RC0[31], RC1[31];
	uint16_t xk[16], xb[16];
	int i;

	/*
	 * Decode key and input block.
	 */
	for (i = 0; i < 16; i ++) {
		xk[i] = key[i << 1] + ((uint16_t)key[(i << 1) + 1] << 8);
		xb[i] = buf[i << 1] + ((uint16_t)buf[(i << 1) + 1] << 8);
	}

	/*
	 * Compute round constants.
	 */
	make_round_constants(R, D, RC0, RC1);

	/*
	 * Run all rounds (two rounds per super-round).
	 */
	for (i = R - 1; i >= 0; i --) {
		/*
		 * Odd round.
		 */
		if ((i & 1) == 0) {
			/*
			 * Round r = 1 mod 4.
			 */
			XOR_key_rotated(xk, xb);
			xb[0] ^= RC0[i];
			xb[8] ^= RC1[i];
			SR_slice(xb);
			MDS_inv(xb);
			SR_slice_inv(xb);
		} else {
			/*
			 * Round r = 3 mod 4.
			 */
			XOR_key(xk, xb);
			xb[0] ^= RC0[i];
			xb[8] ^= RC1[i];
			SR_sheet(xb);
			MDS_inv(xb);
			SR_sheet_inv(xb);
		}
		S_box_inv(xb);

		/*
		 * Even round.
		 */
		MDS_inv(xb);
		S_box_inv(xb);
	}

	/*
	 * XOR key into state.
	 */
	XOR_key(xk, xb);

	/*
	 * Encode output block.
	 */
	for (i = 0; i < 16; i ++) {
		buf[(i << 1) + 0] = (uint8_t)xb[i];
		buf[(i << 1) + 1] = (uint8_t)(xb[i] >> 8);
	}
}
