/**
 * The PAEF forkcipher mode of operation.
 * 
 * @file paef.h
 * @author Antoon Purnal <antoon.purnal@esat.kuleuven.be>
 */

#ifndef PAEF_H
#define PAEF_H 

int paef_encrypt(
	unsigned char *c,
	const unsigned char *m,unsigned long long mlen,
	const unsigned char *ad,unsigned long long adlen,
	const unsigned char *npub,
	const unsigned char *k
	); 


int paef_decrypt(
	unsigned char *m,
	const unsigned char *c,unsigned long long clen,
	const unsigned char *ad,unsigned long long adlen,
	const unsigned char *npub,
	const unsigned char *k
	); 

#endif /* ifndef PAEF_H */
