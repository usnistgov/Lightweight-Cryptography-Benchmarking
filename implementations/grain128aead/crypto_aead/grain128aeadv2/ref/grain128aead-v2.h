#ifndef GRAIN128AEAD_H
#define GRAIN128AEAD_H

#define STREAM_BYTES	16
#define MSG_BYTES		0

enum GRAIN_ROUND {INIT, ADDKEY, NORMAL};

typedef struct {
	unsigned char lfsr[128];
	unsigned char nfsr[128];
	unsigned char auth_acc[64];
	unsigned char auth_sr[64];
} grain_state;

typedef struct {
	unsigned char *message;
	unsigned long long msg_len;
} grain_data;

void init_grain(grain_state *grain, const unsigned char *key, const unsigned char *iv);
unsigned char next_lfsr_fb(grain_state *grain);
unsigned char next_nfsr_fb(grain_state *grain);
unsigned char next_h(grain_state *grain);
unsigned char shift(unsigned char fsr[128], unsigned char fb);
void auth_shift(unsigned char sr[32], unsigned char fb);
unsigned char next_z(grain_state *grain, unsigned char, unsigned char);
void generate_keystream(grain_state *grain, grain_data *data, unsigned char *);
int encode_der(unsigned long long, unsigned char **);

#endif
