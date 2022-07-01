typedef struct ___skinny_ctrl {
    unsigned char roundKeys[704]; // number of round : 40
    void (*func_skinny_128_384_enc)(unsigned char*, struct ___skinny_ctrl*, unsigned char* CNT, unsigned char* T, const unsigned char* K);
} skinny_ctrl;

extern void skinny_128_384_enc123_12 (unsigned char* input, skinny_ctrl* pskinny_ctrl, unsigned char* CNT, unsigned char* T, const unsigned char* K);
extern void skinny_128_384_enc12_12 (unsigned char* input, skinny_ctrl* pskinny_ctrl, unsigned char* CNT, unsigned char* T, const unsigned char* K);
extern void skinny_128_384_enc1_1 (unsigned char* input, skinny_ctrl* pskinny_ctrl, unsigned char* CNT, unsigned char* T, const unsigned char* K);
