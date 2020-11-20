#ifdef __cplusplus
extern "C" {
#endif

int crypto_hash(
	unsigned char *out,
	const unsigned char *in,
	unsigned long long inlen
	);

#ifdef __cplusplus
}
#endif