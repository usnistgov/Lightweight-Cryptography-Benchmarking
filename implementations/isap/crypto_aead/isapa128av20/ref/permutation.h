#ifndef ISAP_PERMUTATION_H
#define ISAP_PERMUTATION_H

void Permutation_Initialize(
	const void *state
);

void Permutation_AddBytes(
	void *state,
	const unsigned char *data,
	size_t offset,
	size_t length
);

void Permutation_OverwriteBytes(
	void *state,
	const unsigned char *data,
	size_t offset,
	size_t length
);

void Permutation_Permute_Nrounds(
	void *state,
	size_t nrounds
);

void Permutation_ExtractBytes(
	const void *state,
	unsigned char *data,
	size_t offset,
	size_t length
);

#endif

