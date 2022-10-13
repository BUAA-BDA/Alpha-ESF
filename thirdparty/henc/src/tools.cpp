/*
 * This is written by Lulu Han.
 * E-mail: locomotive_crypto@163.com
 */

#include "tools.h"

void rsa_param(NTL::ZZ& p, NTL::ZZ& q, long bitlens){
	NTL::RandomPrime(p, bitlens, 80);
	NTL::RandomPrime(q, bitlens, 80);
}

void dl_param(NTL::ZZ& p, NTL::ZZ& g, long mod_bitlens, long group_bitlens){
	long qlen = group_bitlens;
	long klen = mod_bitlens - qlen;
	NTL::ZZ q, k;
	
	NTL::RandomPrime(q, qlen, 80);
	while(true){
		NTL::RandomLen(k, klen);
		p = k * q + 1;
		if(NTL::ProbPrime(p, 80))
			break;
	}
	
	NTL::ZZ r;
	while(true){
		r = NTL::RandomBnd(p - 1) + 1;
		g = NTL::PowerMod(r, k, p);
		if(g != 1)
			break;
	}
}
