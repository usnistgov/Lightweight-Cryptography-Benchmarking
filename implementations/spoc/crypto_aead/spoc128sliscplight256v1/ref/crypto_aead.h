typedef unsigned long long u64;

int spoc128_init(
			unsigned char *state, 
			const unsigned char *npub,
			const unsigned char *k
			);
int spoc128_ad(
			unsigned char *state,
			const unsigned char *ad, 
			const u64 adlen
		     );

int spoc128_gentag(
			unsigned char *tag, 
			const unsigned char tlen,
			unsigned char *state 
			);

int crypto_aead_encrypt(
	unsigned char *c, unsigned long long *clen,
	const unsigned char *m, unsigned long long mlen,
	const unsigned char *ad, unsigned long long adlen,
	const unsigned char *nsec,
	const unsigned char *npub,
	const unsigned char *k
);

int crypto_aead_decrypt(
	unsigned char *m, unsigned long long *mlen,
	unsigned char *nsec,
	const unsigned char *c, unsigned long long clen,
	const unsigned char *ad, unsigned long long adlen,
	const unsigned char *npub,
	const unsigned char *k
);

int spoc128_gentag(
                   unsigned char *tag,
                   const unsigned char tlen,
                   unsigned char *state
                   );
