/*
 * This is written by Lulu Han.
 * E-mail: locomotive_crypto@163.com
 */

#include "paillier.h"
#include "tools.h"

Paillier::SecretKey::SecretKey(const NTL::ZZ& p, const NTL::ZZ& q){
	this->N = p*q;
	this->phi_N = (p-1)*(q-1);
	this->phi_N_inv = NTL::InvMod(this->phi_N, this->N);
	this->N_square = this->N * this->N;
}

NTL::ZZ Paillier::SecretKey::get_phi_N(){
	return this->phi_N;
}

NTL::ZZ Paillier::SecretKey::get_phi_N_inv(){
	return this->phi_N_inv;
}

NTL::ZZ Paillier::SecretKey::get_N(){
	return this->N;
}

NTL::ZZ Paillier::SecretKey::get_N_square(){
	return this->N_square;
}

Paillier::PublicKey::PublicKey(const NTL::ZZ& N){
	this->N = N;
	this->G = N + 1;
	this->N_square = N * N;
}

NTL::ZZ Paillier::PublicKey::get_N(){
	return this->N;
}

NTL::ZZ Paillier::PublicKey::get_G(){
	return this->G;
}

NTL::ZZ Paillier::PublicKey::get_N_square(){
	return this->N_square;
}

Paillier::Encryptor::Encryptor(const PublicKey& pk): m_pk(pk){
	// ... 
}

void Paillier::Encryptor::encrypt(const HEnc::PTxt& pt, HEnc::CTxt& ct){
	// Generate a random value r
	NTL::ZZ r; //  1 < r < N
	while(true){
		r = NTL::RandomBnd(m_pk.get_N());
		if (NTL::GCD(r, m_pk.get_N()) == 1 && r > 1)
			break;
	}
	
	// Encrypt message m
	NTL::ZZ tmp, c, m;
	m = pt.get_pt();
	tmp = NTL::PowerMod(r, m_pk.get_N(), m_pk.get_N_square());
	NTL::mul(c, m, m_pk.get_N());
	c = NTL::AddMod(c, 1, m_pk.get_N_square());
	c = NTL::MulMod(tmp, c, m_pk.get_N_square());
	ct.set_ct(c);
}

void Paillier::Encryptor::he_sub(const HEnc::CTxt& ct1, const HEnc::CTxt& ct2, HEnc::CTxt& ct){
	NTL::ZZ c1, c2, c;
	c1 = ct1.get_ct();
	c2 = ct2.get_ct();
	NTL::InvMod(c2, c2, m_pk.get_N_square());
	c = NTL::MulMod(c1, c2, m_pk.get_N_square());
	
	ct.set_ct(c);
}

void Paillier::Encryptor::he_add(const HEnc::CTxt& ct1, const HEnc::CTxt& ct2, HEnc::CTxt& ct){
	NTL::ZZ c1, c2, c;
	c1 = ct1.get_ct();
	c2 = ct2.get_ct();
	
	c = NTL::MulMod(c1, c2, m_pk.get_N_square());
	
	ct.set_ct(c);
}

void Paillier::Encryptor::he_add(const HEnc::CTxt& ct1, const HEnc::PTxt& pt1, HEnc::CTxt& ct){
	HEnc::CTxt pt1_ct;
	
	this->encrypt(pt1, pt1_ct);
	this->he_add(ct1, pt1_ct, ct);
}

void Paillier::Encryptor::he_add(const HEnc::PTxt& pt1, const HEnc::CTxt& ct1, HEnc::CTxt& ct){
	this->he_add(ct1, pt1, ct);
}

void Paillier::Encryptor::he_mul(const HEnc::CTxt& ct1, const HEnc::PTxt& pt1, HEnc::CTxt& ct){
	NTL::ZZ c1, m1, c;
	c1 = ct1.get_ct();
	m1 = pt1.get_pt();
	
	c = NTL::PowerMod(c1, m1, m_pk.get_N_square());
	
	ct.set_ct(c);
}

void Paillier::Encryptor::he_mul(const HEnc::PTxt& pt1, const HEnc::CTxt& ct1, HEnc::CTxt& ct){
	this->he_mul(ct1, pt1, ct);
}

Paillier::Decryptor::Decryptor(const SecretKey& sk): m_sk(sk){
	// ...
}

void Paillier::Decryptor::decrypt(const HEnc::CTxt& ct, HEnc::PTxt& pt){
	NTL::ZZ tmp, c, m;
	c = ct.get_ct();
	tmp = NTL::PowerMod(c, m_sk.get_phi_N(), m_sk.get_N_square());
	tmp -= 1;
	NTL::divide(tmp, tmp, m_sk.get_N());
	m = NTL::MulMod(tmp, m_sk.get_phi_N_inv(), m_sk.get_N());
	pt.set_pt(m);
}

void Paillier::key_gen(SecretKey& sk, PublicKey& pk, long bitlens){
	// Generate two random prime numbers
	NTL::ZZ p, q;
	
	rsa_param(p, q, bitlens);
	
	// Generate key pair
	SecretKey skey(p, q);
	PublicKey pkey(p*q);
	
	sk = skey;
	pk = pkey;
}

void Paillier::key_gen(SecretKey& sk, PublicKey& pk, long bitlens, NTL::ZZ& p, NTL::ZZ& q){
	// Generate two random prime numbers
	// NTL::ZZ p, q;
	
	rsa_param(p, q, bitlens);
	
	// Generate key pair
	SecretKey skey(p, q);
	PublicKey pkey(p*q);
	
	sk = skey;
	pk = pkey;
}

void Paillier::key_load(SecretKey& sk, PublicKey& pk,  NTL::ZZ& p, NTL::ZZ& q){
	// Generate two random prime numbers
	// NTL::ZZ p, q;
	
	// rsa_param(p, q, bitlens);
	
	// Generate key pair
	SecretKey skey(p, q);
	PublicKey pkey(p*q);
	
	sk = skey;
	pk = pkey;
}
