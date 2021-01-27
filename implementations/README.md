This folder contains the implementations of Round 2 candidates collected from the submission packages and following repositories:

 - https://github.com/nerilex/arm-crypto-lib
 - https://github.com/aadomn/skinny
 - https://github.com/ArneDeprez1/ForkAE-SW
 - https://github.com/ascon/ascon-c
 - https://github.com/sebastien-riou/DryGASCON
 - https://github.com/TimBeyne/Elephant
 - https://github.com/cryptolu/FELICS
 - https://github.com/ARMmbed/mbedtls
 - https://nacl.cr.yp.to/
 - https://lab.las3.de/gitlab/lwc/candidates
 - https://github.com/rweather/lightweight-crypto
	

The implementations have been updated on: **2 December 2020**.

## Directory structure

The directory structure of the implementations is as follows:

```
- [submission_name]
    - crypto_aead
        - [aead_variant1]
            - [impl1]
            - [impl2]
        - [aead_variant2]
            - [impl1]
            - [impl2]
    - crypto_hash
        - [hash_variant1]
            - [impl1]
            - [impl2]
```

For the submissions where there was an AEAD and Hash variant with the same name, the folder names have been appended with 'aead' or 'hash' so as to make all the variant names unique.

## Changes made to the implementations and the directories

In each implementation folder, a C file that contains a wrapper for the implementation is added to make it compatible with the *benchmarking framework*:

### AEAD implementations

A file named `lwc_crypto_aead.c` has been aded. This file defines the `aead_ctx` structure declared in `lwc_crypto_aead.h`:

``` c
typedef struct {

	const char* variant_name;
	const char* impl_name;
	int KeyBytes;
	int NonceBytes;
	int ABytes;
	fn_aead_encrypt encrypt;
	fn_aead_decrypt decrypt;

} aead_ctx;
```

An AEAD implementation must have a `lwc_crypto_aead.c` file that defines a `aead_ctx` with the name `lwc_aead_cipher`. Here's an example:

``` c
#include "lwc_crypto_aead.h"
#include "api.h"

aead_ctx lwc_aead_cipher = {
	"aes-gcm",
	"mbedtls",
	CRYPTO_KEYBYTES,
	CRYPTO_NPUBBYTES,
	CRYPTO_ABYTES,
	crypto_aead_encrypt,
	crypto_aead_decrypt
};
```

### Hash implementations

Similar to the AEAD case, a file named `lwc_crypto_hash.c` which defines the `hash_ctx` structure declared in `lwc_crypto_hash.h` is added:

``` c
typedef struct {

	const char* variant_name;
	const char* impl_name;
	int DigestSize;
	fn_hash hash;

} hash_ctx;
```

The `lwc_crypto_hash.c` file must define a variable named `lwc_hash_ctx` of type `hash_ctx`. Here's a sample `lwc_crypto_hash.c` file:

``` c
#include "lwc_crypto_hash.h"
#include "api.h"

hash_ctx lwc_hash_ctx = {
	"sha256",
	"mbedtls",
	CRYPTO_BYTES,
	crypto_hash,
};
```

**Note:** The `lwc_crypto_aead.c` and `lwc_crypto_hash.c` files make use of the `api.h` file in order to define algorithm parameters such as Key Length, Nonce Length, etc. If an implementation did not have this file, it was copied from the *reference implementation* of the variant.


## Other changes

The following files are used as markers for the build script:

 - An empty file named `primary` is added under the primary variant folders.
 - For Assembly implementations, an empty file `lwc_arc_[archname]` is added in order to avoid the compilation of the implementation on incompatible architectures.


For implementations that require an input sizes to be a multiple of *k > 1* bytes, a file named `lwc_constraints.h` is added. If this file does not exist in the implementation directory then it is assumed that the implementation handles inputs of all sizes. As an example, if an AEAD implementation requires the plaintext length to be a multiple of 4 bytes, then the `lwc_constraints.h` file must have the following content:
 ``` c
 #define LWC_MLEN_STEP 4
 ```
The `LWC_MLEN_STEP` definition can be used to specify input size constraints for both the *plaintext length* for AEAD and the *message length* for Hash functions. Similarly, `LWC_ALEN_STEP` can be used to specify input constraints for the associated data length.

