/*
 * This is written by Lulu Han.
 * E-mail: locomotive_crypto@163.com
 */
#include <exception>
#include "elgamal.h"
#include "tools.h"

Elgamal::SecretKey::SecretKey(const NTL::ZZ& p, const NTL::ZZ& g, const NTL::ZZ& sk){
	m_p = p;
	m_g = g;
	m_sk = sk;
}

NTL::ZZ Elgamal::SecretKey::get_P() const{
	return m_p;
}

NTL::ZZ Elgamal::SecretKey::get_G() const{
	return m_g;
}

NTL::ZZ Elgamal::SecretKey::get_sk() const{
	return m_sk;
}

Elgamal::PublicKey::PublicKey(const NTL::ZZ& p, const NTL::ZZ& g, const NTL::ZZ& pk){
	m_p = p;
	m_g = g;
	m_pk = pk;
}

NTL::ZZ Elgamal::PublicKey::get_P() const{
	return m_p;
}

NTL::ZZ Elgamal::PublicKey::get_G() const{
	return m_g;
}

NTL::ZZ Elgamal::PublicKey::get_pk() const{
	return m_pk;
}
		
Elgamal::Encryptor::Encryptor(const PublicKey& pk):m_pk(pk){
	// ...
}

void Elgamal::Encryptor::encrypt(const HEnc::PTxt& pt, HEnc::CTxt& ct){
	NTL::ZZ r, m, c1, c2;
	m = pt.get_pt();
	
	r = NTL::RandomBnd(m_pk.get_P() - 2) + 2;
	c1 = NTL::MulMod(m, 
		NTL::PowerMod(m_pk.get_pk(), r,  m_pk.get_P()), 
			m_pk.get_P());
	c2 = NTL::PowerMod(m_pk.get_G(), r, m_pk.get_P());
	
	ct.set_ct1(c1);
	ct.set_ct2(c2);
}

void Elgamal::Encryptor::he_mul(const HEnc::CTxt& ct1, const HEnc::PTxt& pt1, HEnc::CTxt& ct){
	HEnc::CTxt tmp;
	this->encrypt(pt1, tmp);
	this->he_mul(tmp, ct1, ct);
}

void Elgamal::Encryptor::he_mul(const HEnc::PTxt& pt1, const HEnc::CTxt& ct1, HEnc::CTxt& ct){
	this->he_mul(ct1, pt1, ct);
}

void Elgamal::Encryptor::he_mul(const HEnc::CTxt& ct1, const HEnc::CTxt& ct2, HEnc::CTxt& ct){
	NTL::ZZ c11, c12, c21, c22, c1, c2;
	c11 = ct1.get_ct1();
	c12 = ct1.get_ct2();
	
	c21 = ct2.get_ct1();
	c22 = ct2.get_ct2();
	
	c1 = NTL::MulMod(c11, c21, m_pk.get_P());
	c2 = NTL::MulMod(c12, c22, m_pk.get_P());
	
	ct.set_ct1(c1);
	ct.set_ct2(c2);
}


Elgamal::Decryptor::Decryptor(const SecretKey& sk):m_sk(sk){
	// ...
}

void Elgamal::Decryptor::decrypt(const HEnc::CTxt& ct, HEnc::PTxt& pt){
	NTL::ZZ c1, c2, t, invt, m;
	
	c1 = ct.get_ct1();
	c2 = ct.get_ct2();
	
	t = NTL::PowerMod(c2, m_sk.get_sk(), m_sk.get_P());
	invt = NTL::InvMod(t, m_sk.get_P());
	m = NTL::MulMod(c1, invt, m_sk.get_P());
	
	pt.set_pt(m);
}

void Elgamal::key_gen(SecretKey& sk, PublicKey& pk, long mod_bitlens, long group_bitlens){
	if(group_bitlens >= mod_bitlens){
		throw std::runtime_error("The parameters is invalid...");
	}
	
	NTL::ZZ p, g;
	
	dl_param(p, g, mod_bitlens, group_bitlens);
	
	NTL::ZZ sk_z, pk_z;
	sk_z = NTL::RandomBnd(p - 2) + 2;
	pk_z = NTL::PowerMod(g, sk_z, p);
	
	SecretKey skey(p, g, sk_z);
	PublicKey pkey(p, g, pk_z);
	
	sk = skey;
	pk = pkey;
}
