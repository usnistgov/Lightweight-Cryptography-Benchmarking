#ifndef __DRYGASCON128CORE_H__
#define __DRYGASCON128CORE_H__

#define DRYGASCON_G_OPT   drysponge128_g_impl
#define DRYGASCON_F_OPT   drygascon128_f_opt_le32

/* Generic right rotate */
#define rightRotate(a, bits) \
    (__extension__ ({ \
        uint32_t _temp = (a); \
        (_temp >> (bits)) | (_temp << (32 - (bits))); \
    }))

#define rightRotate1(a)  (rightRotate((a), 1))

/* Right rotations in bit-interleaved format */
#define intRightRotateEven(x,bits) \
    (__extension__ ({ \
        uint32_t _x0 = (uint32_t)(x); \
        uint32_t _x1 = (uint32_t)((x) >> 32); \
        _x0 = rightRotate(_x0, (bits)); \
        _x1 = rightRotate(_x1, (bits)); \
        _x0 | (((uint64_t)_x1) << 32); \
    }))
#define intRightRotateOdd(x,bits) \
    (__extension__ ({ \
        uint32_t _x0 = (uint32_t)(x); \
        uint32_t _x1 = (uint32_t)((x) >> 32); \
        _x0 = rightRotate(_x0, ((bits) + 1) % 32); \
        _x1 = rightRotate(_x1, (bits)); \
        _x1 | (((uint64_t)_x0) << 32); \
    }))
#define intRightRotate1_64(x) \
    (__extension__ ({ \
        uint32_t _x0 = (uint32_t)(x); \
        uint32_t _x1 = (uint32_t)((x) >> 32); \
        _x0 = rightRotate1(_x0); \
        _x1 | (((uint64_t)_x0) << 32); \
    }))
#define intRightRotate2_64(x)  (intRightRotateEven((x), 1))
#define intRightRotate3_64(x)  (intRightRotateOdd((x), 1))
#define intRightRotate4_64(x)  (intRightRotateEven((x), 2))
#define intRightRotate5_64(x)  (intRightRotateOdd((x), 2))
#define intRightRotate6_64(x)  (intRightRotateEven((x), 3))
#define intRightRotate7_64(x)  (intRightRotateOdd((x), 3))
#define intRightRotate8_64(x)  (intRightRotateEven((x), 4))
#define intRightRotate9_64(x)  (intRightRotateOdd((x), 4))
#define intRightRotate10_64(x) (intRightRotateEven((x), 5))
#define intRightRotate11_64(x) (intRightRotateOdd((x), 5))
#define intRightRotate12_64(x) (intRightRotateEven((x), 6))
#define intRightRotate13_64(x) (intRightRotateOdd((x), 6))
#define intRightRotate14_64(x) (intRightRotateEven((x), 7))
#define intRightRotate15_64(x) (intRightRotateOdd((x), 7))
#define intRightRotate16_64(x) (intRightRotateEven((x), 8))
#define intRightRotate17_64(x) (intRightRotateOdd((x), 8))
#define intRightRotate18_64(x) (intRightRotateEven((x), 9))
#define intRightRotate19_64(x) (intRightRotateOdd((x), 9))
#define intRightRotate20_64(x) (intRightRotateEven((x), 10))
#define intRightRotate21_64(x) (intRightRotateOdd((x), 10))
#define intRightRotate22_64(x) (intRightRotateEven((x), 11))
#define intRightRotate23_64(x) (intRightRotateOdd((x), 11))
#define intRightRotate24_64(x) (intRightRotateEven((x), 12))
#define intRightRotate25_64(x) (intRightRotateOdd((x), 12))
#define intRightRotate26_64(x) (intRightRotateEven((x), 13))
#define intRightRotate27_64(x) (intRightRotateOdd((x), 13))
#define intRightRotate28_64(x) (intRightRotateEven((x), 14))
#define intRightRotate29_64(x) (intRightRotateOdd((x), 14))
#define intRightRotate30_64(x) (intRightRotateEven((x), 15))
#define intRightRotate31_64(x) (intRightRotateOdd((x), 15))
#define intRightRotate32_64(x) (intRightRotateEven((x), 16))
#define intRightRotate33_64(x) (intRightRotateOdd((x), 16))
#define intRightRotate34_64(x) (intRightRotateEven((x), 17))
#define intRightRotate35_64(x) (intRightRotateOdd((x), 17))
#define intRightRotate36_64(x) (intRightRotateEven((x), 18))
#define intRightRotate37_64(x) (intRightRotateOdd((x), 18))
#define intRightRotate38_64(x) (intRightRotateEven((x), 19))
#define intRightRotate39_64(x) (intRightRotateOdd((x), 19))
#define intRightRotate40_64(x) (intRightRotateEven((x), 20))
#define intRightRotate41_64(x) (intRightRotateOdd((x), 20))
#define intRightRotate42_64(x) (intRightRotateEven((x), 21))
#define intRightRotate43_64(x) (intRightRotateOdd((x), 21))
#define intRightRotate44_64(x) (intRightRotateEven((x), 22))
#define intRightRotate45_64(x) (intRightRotateOdd((x), 22))
#define intRightRotate46_64(x) (intRightRotateEven((x), 23))
#define intRightRotate47_64(x) (intRightRotateOdd((x), 23))
#define intRightRotate48_64(x) (intRightRotateEven((x), 24))
#define intRightRotate49_64(x) (intRightRotateOdd((x), 24))
#define intRightRotate50_64(x) (intRightRotateEven((x), 25))
#define intRightRotate51_64(x) (intRightRotateOdd((x), 25))
#define intRightRotate52_64(x) (intRightRotateEven((x), 26))
#define intRightRotate53_64(x) (intRightRotateOdd((x), 26))
#define intRightRotate54_64(x) (intRightRotateEven((x), 27))
#define intRightRotate55_64(x) (intRightRotateOdd((x), 27))
#define intRightRotate56_64(x) (intRightRotateEven((x), 28))
#define intRightRotate57_64(x) (intRightRotateOdd((x), 28))
#define intRightRotate58_64(x) (intRightRotateEven((x), 29))
#define intRightRotate59_64(x) (intRightRotateOdd((x), 29))
#define intRightRotate60_64(x) (intRightRotateEven((x), 30))
#define intRightRotate61_64(x) (intRightRotateOdd((x), 30))
#define intRightRotate62_64(x) (intRightRotateEven((x), 31))
#define intRightRotate63_64(x) (intRightRotateOdd((x), 31))

void gascon128_core_round(gascon128_state_t *state, uint8_t round)
{
    uint64_t t0, t1, t2, t3, t4;

    /* Load the state into local varaibles */
    uint64_t x0 = state->S[0];
    uint64_t x1 = state->S[1];
    uint64_t x2 = state->S[2];
    uint64_t x3 = state->S[3];
    uint64_t x4 = state->S[4];

    /* Add the round constant to the middle of the state */
    x2 ^= ((0x0F - round) << 4) | round;

    /* Substitution layer */
    x0 ^= x4; x2 ^= x1; x4 ^= x3; t0 = (~x0) & x1; t1 = (~x1) & x2;
    t2 = (~x2) & x3; t3 = (~x3) & x4; t4 = (~x4) & x0; x0 ^= t1;
    x1 ^= t2; x2 ^= t3; x3 ^= t4; x4 ^= t0; x1 ^= x0; x3 ^= x2;
    x0 ^= x4; x2 = ~x2;

    /* Linear diffusion layer */
    x0 ^= intRightRotate19_64(x0) ^ intRightRotate28_64(x0);
    x1 ^= intRightRotate61_64(x1) ^ intRightRotate38_64(x1);
    x2 ^= intRightRotate1_64(x2)  ^ intRightRotate6_64(x2);
    x3 ^= intRightRotate10_64(x3) ^ intRightRotate17_64(x3);
    x4 ^= intRightRotate7_64(x4)  ^ intRightRotate40_64(x4);

    /* Write the local variables back to the state */
    state->S[0] = x0;
    state->S[1] = x1;
    state->S[2] = x2;
    state->S[3] = x3;
    state->S[4] = x4;
}

//use state only to access c,r,x
static void drysponge128_g_impl(drysponge128_state_t *state,unsigned int rounds)
{
    unsigned round;

    /* Perform the first round.  For each round we XOR the 16 bytes of
     * the output data with the first 16 bytes of the state.  And then
     * XOR with the next 16 bytes of the state, rotated by 4 bytes */
    gascon128_core_round(&(state->c), 0);
    state->r.W[0] = state->c.W[0] ^ state->c.W[5];
    state->r.W[1] = state->c.W[1] ^ state->c.W[6];
    state->r.W[2] = state->c.W[2] ^ state->c.W[7];
    state->r.W[3] = state->c.W[3] ^ state->c.W[4];

    /* Perform the rest of the rounds */
    for (round = 1; round < rounds; ++round) {
        gascon128_core_round(&(state->c), round);
        state->r.W[0] ^= state->c.W[0] ^ state->c.W[5];
        state->r.W[1] ^= state->c.W[1] ^ state->c.W[6];
        state->r.W[2] ^= state->c.W[2] ^ state->c.W[7];
        state->r.W[3] ^= state->c.W[3] ^ state->c.W[4];
    }
}

static void drysponge128_g_core(drysponge128_state_t *state)
{
    unsigned round;
    for (round = 0; round < state->rounds; ++round)
        gascon128_core_round(&(state->c), round);
}

/**
 * \fn uint32_t drysponge_select_x(const uint32_t x[4], uint8_t index)
 * \brief Selects an element of x in constant time.
 *
 * \param x Points to the four elements of x.
 * \param index Index of which element to extract between 0 and 3.
 *
 * \return The selected element of x.
 */
#define drysponge_select_x(x, index) ((x)[(index)])


/**
 * \brief Mixes a 32-bit value into the DrySPONGE128 state.
 *
 * \param state DrySPONGE128 state.
 * \param data The data to be mixed in the bottom 10 bits.
 */
static void drysponge128_mix_phase_round
    (drysponge128_state_t *state, uint32_t data)
{
    /* Mix in elements from x according to the 2-bit indexes in the data */
    state->c.W[0] ^= drysponge_select_x(state->x.W, data & 0x03);
    state->c.W[2] ^= drysponge_select_x(state->x.W, (data >> 2) & 0x03);
    state->c.W[4] ^= drysponge_select_x(state->x.W, (data >> 4) & 0x03);
    state->c.W[6] ^= drysponge_select_x(state->x.W, (data >> 6) & 0x03);
    state->c.W[8] ^= drysponge_select_x(state->x.W, (data >> 8) & 0x03);
}

/**
 * \brief Mixes an input block into a DrySPONGE128 state.
 *
 * \param state The DrySPONGE128 state.
 * \param data Full rate block containing the input data.
 */
static void drysponge128_mix_phase
    (drysponge128_state_t *state, const unsigned char data[DRYSPONGE128_RATE],unsigned int ds)
{
    /* Mix 10-bit groups into the output, with the domain
     * separator added to the last two groups */
    drysponge128_mix_phase_round
        (state, data[0] | (((uint32_t)(data[1])) << 8));
    gascon128_core_round(&(state->c), 0);
    drysponge128_mix_phase_round
        (state, (data[1] >> 2) | (((uint32_t)(data[2])) << 6));
    gascon128_core_round(&(state->c), 0);
    drysponge128_mix_phase_round
        (state, (data[2] >> 4) | (((uint32_t)(data[3])) << 4));
    gascon128_core_round(&(state->c), 0);
    drysponge128_mix_phase_round
        (state, (data[3] >> 6) | (((uint32_t)(data[4])) << 2));
    gascon128_core_round(&(state->c), 0);
    drysponge128_mix_phase_round
        (state, data[5] | (((uint32_t)(data[6])) << 8));
    gascon128_core_round(&(state->c), 0);
    drysponge128_mix_phase_round
        (state, (data[6] >> 2) | (((uint32_t)(data[7])) << 6));
    gascon128_core_round(&(state->c), 0);
    drysponge128_mix_phase_round
        (state, (data[7] >> 4) | (((uint32_t)(data[8])) << 4));
    gascon128_core_round(&(state->c), 0);
    drysponge128_mix_phase_round
        (state, (data[8] >> 6) | (((uint32_t)(data[9])) << 2));
    gascon128_core_round(&(state->c), 0);
    drysponge128_mix_phase_round
        (state, data[10] | (((uint32_t)(data[11])) << 8));
    gascon128_core_round(&(state->c), 0);
    drysponge128_mix_phase_round
        (state, (data[11] >> 2) | (((uint32_t)(data[12])) << 6));
    gascon128_core_round(&(state->c), 0);
    drysponge128_mix_phase_round
        (state, (data[12] >> 4) | (((uint32_t)(data[13])) << 4));
    gascon128_core_round(&(state->c), 0);
    drysponge128_mix_phase_round
        (state, ((data[13] >> 6) | (((uint32_t)(data[14])) << 2)));
    gascon128_core_round(&(state->c), 0);
    drysponge128_mix_phase_round(state, data[15] ^ ds);
    gascon128_core_round(&(state->c), 0);
    drysponge128_mix_phase_round(state, ds >> 10);
}

static void DRYGASCON_F_OPT(drysponge128_state_t *state, const unsigned char *input,unsigned int ds, unsigned int rounds){
    drysponge128_mix_phase(state, input ,ds);
    drysponge128_g_impl(state,rounds);
}


#endif
