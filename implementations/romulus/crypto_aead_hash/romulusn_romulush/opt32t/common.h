void lfsr_gf56 (unsigned char* CNT);
void nonce_encryption (
    const unsigned char* N,
    unsigned char* CNT,
    unsigned char*s, const unsigned char* k,
    unsigned char D,
    skinny_ctrl* p_skinny_ctrl);
unsigned long long ad_encryption_ud16(
    const unsigned char** A, unsigned char* s,
    unsigned long long adlen,
    unsigned char* CNT);
unsigned long long ad_encryption_eq16 (
    const unsigned char** A, unsigned char* s,
    unsigned char* CNT);
unsigned long long ad_encryption_ov16 (
    const unsigned char** A, unsigned char* s,
    const unsigned char* k, unsigned long long adlen,
    unsigned char* CNT,
    unsigned char D,
    skinny_ctrl* p_skinny_ctrl);
unsigned long long ad_encryption_eqov32 (
    const unsigned char** A, unsigned char* s,
    const unsigned char* k, unsigned long long adlen,
    unsigned char* CNT,
    unsigned char D,
    skinny_ctrl* p_skinny_ctrl);
unsigned long long msg_encryption_ud16 (
    const unsigned char** M, unsigned char** c,
    const unsigned char* N,
    unsigned char* CNT,
    unsigned char*s, const unsigned char* k,
    unsigned char D,
    unsigned long long mlen,
    skinny_ctrl* p_skinny_ctrl);
unsigned long long msg_encryption_eqov16 (
    const unsigned char** M, unsigned char** c,
    const unsigned char* N,
    unsigned char* CNT,
    unsigned char*s, const unsigned char* k,
    unsigned char D,
    unsigned long long mlen,
    skinny_ctrl* p_skinny_ctrl);
void generate_tag (
    unsigned char** c, unsigned char* s,
    unsigned long long* clen);
void g8A (unsigned char* s, unsigned char* c);
void pad (const unsigned char* m, unsigned char* mp, int len8);
void reset_lfsr_gf56 (unsigned char* CNT);
void g8A_for_Tag_Generation (unsigned char* s, unsigned char* c);
