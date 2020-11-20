/**
 * The SAEF forkcipher mode of operation.
 * 
 * @file saef.h
 * @author Antoon Purnal <antoon.purnal@esat.kuleuven.be>
 */

#ifndef SAEF_H
#define SAEF_H

int saef_encrypt(
	unsigned char *c,
	const unsigned char *m,unsigned long long mlen,
	const unsigned char *ad,unsigned long long adlen,
	const unsigned char *npub,
	const unsigned char *k
	); 


int saef_decrypt(
	unsigned char *m,
	const unsigned char *c,unsigned long long clen,
	const unsigned char *ad,unsigned long long adlen,
	const unsigned char *npub,
	const unsigned char *k
	); 

#endif /* ifndef SAEF_H */

