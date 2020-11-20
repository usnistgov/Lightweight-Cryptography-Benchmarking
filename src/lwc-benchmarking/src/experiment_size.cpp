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


#if defined(LWC_MODE_USE_AEAD_ENCRYPT) || defined(LWC_MODE_USE_AEAD_DECRYPT) || defined(LWC_MODE_USE_AEAD_BOTH)
int use_aead()
{
	buffer<32> key;
	buffer<32> nonce;
	buffer<32> buf;
	unsigned long long len;
	int ret;

	key.init();
	nonce.init();
	buf.init();

#if defined(LWC_MODE_USE_AEAD_ENCRYPT) || defined(LWC_MODE_USE_AEAD_BOTH)
	ret = lwc_aead_cipher.encrypt(buf.data(), &len, nullptr, 0, nullptr, 0, nullptr, nonce.data(), key.data());
	//SOUT << "crypto_aead_encrypt() returned " << ret << SENDL;
#endif // LWC_MODE_USE_AEAD_ENCRYPT

#if defined(LWC_MODE_USE_AEAD_DECRYPT) || defined(LWC_MODE_USE_AEAD_BOTH)
	ret = lwc_aead_cipher.decrypt(nullptr, &len, nullptr, buf.data(), lwc_aead_cipher.ABytes, nullptr, 0, nonce.data(), key.data());
	//SOUT << "crypto_aead_decrypt() returned " << ret << SENDL;
#endif // LWC_MODE_USE_AEAD_DECRYPT

	return ret;
}
#endif // defined(LWC_MODE_USE_AEAD_ENCRYPT) || defined(LWC_MODE_USE_AEAD_DECRYPT)

#if defined(LWC_MODE_USE_HASH)
int use_hash()
{
	buffer<32> digest;
	int ret = lwc_hash_ctx.hash(digest.data(), nullptr, 0);
	//SOUT << "crypto_hash() returned " << ret << SENDL;
	return ret;
}
#endif // LWC_MODE_USE_HASH



int do_size_experiments()
{
	int ret{ 0 };

#if defined(LWC_MODE_USE_AEAD_ENCRYPT) || defined(LWC_MODE_USE_AEAD_DECRYPT) || defined(LWC_MODE_USE_AEAD_BOTH)
	ret = use_aead();
#endif

#ifdef LWC_MODE_USE_HASH
	ret = use_hash();
#endif

	return ret;
}

