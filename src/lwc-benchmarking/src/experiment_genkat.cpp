//
// NIST-developed software is provided by NIST as a public service.
// You may use, copy and distribute copies of the software in any medium,
// provided that you keep intact this entire notice. You may improve, 
// modify and create derivative works of the software or any portion of
// the software, and you may copy and distribute such modifications or
// works. Modified works should carry a notice stating that you changed
// the software and should note the date and nature of any such change.
// Please explicitly acknowledge the National Institute of Standards and 
// Technology as the source of the software.
//
// NIST-developed software is expressly provided "AS IS." NIST MAKES NO 
// WARRANTY OF ANY KIND, EXPRESS, IMPLIED, IN FACT OR ARISING BY OPERATION
// OF LAW, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTY OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE, NON-INFRINGEMENT AND DATA ACCURACY. NIST
// NEITHER REPRESENTS NOR WARRANTS THAT THE OPERATION OF THE SOFTWARE WILL BE 
// UNINTERRUPTED OR ERROR-FREE, OR THAT ANY DEFECTS WILL BE CORRECTED. NIST 
// DOES NOT WARRANT OR MAKE ANY REPRESENTATIONS REGARDING THE USE OF THE SOFTWARE
// OR THE RESULTS THEREOF, INCLUDING BUT NOT LIMITED TO THE CORRECTNESS, ACCURACY,
// RELIABILITY, OR USEFULNESS OF THE SOFTWARE.
//
// You are solely responsible for determining the appropriateness of using and 
// distributing the software and you assume all risks associated with its use, 
// including but not limited to the risks and costs of program errors, compliance 
// with applicable laws, damage to or loss of data, programs or equipment, and 
// the unavailability or interruption of operation. This software is not intended
// to be used in any situation where a failure could cause risk of injury or 
// damage to property. The software developed by NIST employees is not subject to
// copyright protection within the United States.
//

#include "lwc_benchmark.h"

// Error codes for GENKAT functions
#define KAT_SUCCESS          0
#define KAT_FILE_OPEN_ERROR -1
#define KAT_DATA_ERROR      -3
#define KAT_CRYPTO_FAILURE  -4
#define KAT_INVALID_PARAMETER -5

// required for yield()
#if defined(LWC_EXPERIMENT_GENKAT) && defined(LWC_PLATFORM_NODEMCUV2)
#include <Esp.h>
#endif

#ifdef LWC_MODE_GENKAT_AEAD

int genkat_aead()
{
	const unsigned int MaxMessageBytes = 32;
	const unsigned int MaxAssociatedDataBytes = 32;
	const unsigned int MaxKeyBytes = 32;
	const unsigned int MaxNonceBytes = 32;
	const unsigned int MaxABytes = 32;


	buffer<MaxMessageBytes> msg, msg2;
	buffer<MaxAssociatedDataBytes> ad;
	buffer<MaxKeyBytes> key;
	buffer<MaxNonceBytes> nonce;
	buffer<MaxMessageBytes + MaxABytes> ct;
	unsigned long long clen, mlenDec;
	unsigned int count{1};
	int func_ret, ret_val = KAT_SUCCESS;

	msg.init();
	ad.init();
	key.init();
	nonce.init();

	for (unsigned long long mlen = 0; (mlen <= MaxMessageBytes) && (ret_val == KAT_SUCCESS); mlen += LWC_MLEN_STEP) {

		for (unsigned long long adlen = 0; adlen <= MaxAssociatedDataBytes; adlen += LWC_ALEN_STEP) {

// prevent soft wdt reset
#ifdef LWC_PLATFORM_NODEMCUV2
			yield();
#endif

			SOUT << "Count = " << count << SENDL;
			count++;

			key.print_hex("Key = ", lwc_aead_cipher.KeyBytes);
			nonce.print_hex("Nonce = ", lwc_aead_cipher.NonceBytes);
			msg.print_hex("PT = ", mlen);
			ad.print_hex("AD = ", adlen);

			if ((func_ret = lwc_aead_cipher.encrypt(ct.data(), &clen, msg.data(), mlen, ad.data(), adlen, NULL, nonce.data(), key.data())) != 0) {
				SOUT << "crypto_aead_encrypt returned " << func_ret << SENDL;
				ret_val = KAT_CRYPTO_FAILURE;
				break;
			}

			ct.print_hex("CT = ", clen);

            func_ret = lwc_aead_cipher.decrypt(msg2.data(), &mlenDec, nullptr, ct.data(), clen, ad.data(), adlen, nonce.data(), key.data());        
            
			if(func_ret != 0) {
				SOUT << "crypto_aead_decrypt() failed with code " << func_ret << SENDL;
				ret_val = KAT_CRYPTO_FAILURE;
				break;
			}
                
			// Verify decrypted message length
			if(mlenDec != mlen) {
				SOUT << "incorrect plaintext length, mlen = " << static_cast<uint32_t>(mlen) << " mlenDec = " << static_cast<uint32_t>(mlenDec) << SENDL;
				ret_val = KAT_CRYPTO_FAILURE;
				break;
			}

			// Check if the plaintext is recovered
			if(!compare_buffers(msg.begin(), msg2.begin(), mlen)) {
				SOUT << "decryption did not recover the plaintext" << SENDL;
				msg.print_hex("msg1 = ", mlen);
				msg2.print_hex("msg2 = ", mlen);
				ret_val = KAT_CRYPTO_FAILURE;
				break;
			}

			SOUT << SENDL;
		}
	}

	return ret_val;
}

#endif // LWC_MODE_GENKAT_AEAD


#ifdef LWC_MODE_GENKAT_HASH

int genkat_hash()
{
	const unsigned int MAX_MESSAGE_LENGTH = 1024;
	const unsigned int MAX_DIGEST_LENGTH = 64;

	buffer<MAX_MESSAGE_LENGTH> msg;
	buffer<MAX_DIGEST_LENGTH> digest;
	int ret_val = KAT_SUCCESS;
	int count = 1;

	msg.init();

	for (unsigned long long mlen = 0; mlen <= MAX_MESSAGE_LENGTH; mlen += LWC_MLEN_STEP) {

// prevent soft wdt reset
#ifdef LWC_PLATFORM_NODEMCUV2
			yield();
#endif

		SOUT << "Count = " << count << SENDL;
		count++;

		msg.print_hex("Msg = ", mlen);

		ret_val = lwc_hash_ctx.hash(digest.data(), msg.data(), mlen);
		
		if(ret_val != 0) {
			SOUT << "crypto_hash returned " << ret_val << SENDL;
			ret_val = KAT_CRYPTO_FAILURE;
			break;
		}

		digest.print_hex("MD = ", lwc_hash_ctx.DigestSize);

		SOUT << SENDL;
	}

	return ret_val;
}

#endif // LWC_MODE_GENKAT_HASH



int do_genkat_experiments()
{
	int ret{ 0 };

#ifdef LWC_MODE_GENKAT_AEAD
	ret = genkat_aead();
#endif

#ifdef LWC_MODE_GENKAT_HASH
	ret = genkat_hash();
#endif

	return ret;
}
