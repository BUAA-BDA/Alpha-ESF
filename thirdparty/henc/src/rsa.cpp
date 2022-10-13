/*
 * This is written by Lulu Han.
 * E-mail: locomotive_crypto@163.com
 */

#include "rsa.h"
#include "tools.h"


RSA::SecretKey::SecretKey(const NTL::ZZ& d, const NTL::ZZ& N){
	m_d = d;
	m_N = N;
}

NTL::ZZ RSA::SecretKey::get_d(){
	return m_d;
}

NTL::ZZ RSA::SecretKey::get_N(){
	return m_N;
}
	
RSA::PublicKey::PublicKey(const NTL::ZZ& e, const NTL::ZZ& N){
	m_e = e;
	m_N = N;
}

NTL::ZZ RSA::PublicKey::get_e(){
	return m_e;
}

NTL::ZZ RSA::PublicKey::get_N(){
	return m_N;
}

RSA::Encryptor::Encryptor(const PublicKey& pk){
	m_pk = pk;
}

void RSA::Encryptor::encrypt(const HEnc::PTxt& pt, HEnc::CTxt& ct){
	NTL::ZZ m, c;
	
	m = pt.get_pt();
	
	c = NTL::PowerMod(m, m_pk.get_e(), m_pk.get_N());
	
	ct.set_ct(c);
}

void RSA::Encryptor::he_mul(const HEnc::CTxt& ct1, const HEnc::PTxt& pt1, HEnc::CTxt& ct){
	HEnc::CTxt ct2;
	
	encrypt(pt1, ct2);
	
	he_mul(ct1, ct2, ct);
}

void RSA::Encryptor::he_mul(const HEnc::PTxt& pt1, const HEnc::CTxt& ct1, HEnc::CTxt& ct){
	he_mul(ct1, pt1, ct);
}

void RSA::Encryptor::he_mul(const HEnc::CTxt& ct1, const HEnc::CTxt& ct2, HEnc::CTxt& ct){
	NTL::ZZ c1, c2, c;
	
	c1 = ct1.get_ct();
	c2 = ct2.get_ct();
	
	c = NTL::MulMod(c1, c2, m_pk.get_N());
	
	ct.set_ct(c);
}

RSA::Decryptor::Decryptor(const SecretKey& sk){
	m_sk = sk;
}

void RSA::Decryptor::decrypt(const HEnc::CTxt& ct, HEnc::PTxt& pt){
	NTL::ZZ c, m;
	
	c = ct.get_ct();
	m = NTL::PowerMod(c, m_sk.get_d(), m_sk.get_N());
	
	pt.set_pt(m);
}

void RSA::key_gen(SecretKey& sk, PublicKey& pk, long pqbitlens){
	NTL::ZZ p, q, N;
	
	rsa_param(p, q, pqbitlens);
	
	N = p*q;
	
	NTL::ZZ phi, d, e;
	
	phi = (p-1) * (q-1);
	
	while(true){
		e = NTL::RandomBnd(N-1) + 1;
		if(NTL::GCD(e, phi) == 1)
			break;
	}
	
	d = NTL::InvMod(e, phi);
	
	SecretKey pri(d, N);
	PublicKey pub(e, N);
	
	sk = pri;
	pk = pub;
}
