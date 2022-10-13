/*
 * This is written by Lulu Han and Yunguo Guan.
 * E-mail: locomotive_crypto@163.com
 */

#include <exception>
#include "she.h"

SHE::SecretKey::SecretKey(const NTL::ZZ& p, const NTL::ZZ& q, const NTL::ZZ& L){
	m_N = p*q;
	m_p = p;
	m_q = q;
	m_L = L;
}

NTL::ZZ SHE::SecretKey::get_N() const{
	return m_N;
}

NTL::ZZ SHE::SecretKey::get_p() const{
	return m_p;
}

NTL::ZZ SHE::SecretKey::get_q() const{
	return m_q;
}

NTL::ZZ SHE::SecretKey::get_L() const{
	return m_L;
}

/*
SHE::PublicKey::PublicKey(const NTL::ZZ& N, const NTL::ZZ& e0, const NTL::ZZ& e1, 
	const NTL::ZZ& en1, long k0, long k1, long k2){
	m_N = N;
	m_enc_0 = e0;
	m_enc_1 = e1;
	m_enc_neg_1 = en1;
	
	m_k0 = k0;
	m_k1 = k1;
	m_k2 = k2;
}*/


SHE::PublicKey::PublicKey(const NTL::ZZ& N, const NTL::ZZ& e01, const NTL::ZZ& e02, const NTL::ZZ& e1, 
	const NTL::ZZ& en1, long k0, long k1, long k2){
	m_N = N;
	m_enc_01 = e01;
	m_enc_02 = e02;
	m_enc_1 = e1;
	m_enc_neg_1 = en1;
	
	m_k0 = k0;
	m_k1 = k1;
	m_k2 = k2;
}

NTL::ZZ SHE::PublicKey::get_N() const{
	return m_N;
}

long SHE::PublicKey::get_k2() const{
	return m_k2;
}

long SHE::PublicKey::get_k1() const{
	return m_k1;
}

long SHE::PublicKey::get_mul_depth() const{
	return (m_k0/(2*m_k2) - 1);
}

/*
NTL::ZZ SHE::PublicKey::get_enc0() const{
	return m_enc_0;
}*/

NTL::ZZ SHE::PublicKey::get_enc01() const{
	return m_enc_01;
}

NTL::ZZ SHE::PublicKey::get_enc02() const{
	return m_enc_02;
}
NTL::ZZ SHE::PublicKey::get_enc1() const{
	return m_enc_1;
}

NTL::ZZ SHE::PublicKey::get_encn1() const{
	return m_enc_neg_1;
}

SHE::Encryptor::Encryptor(const PublicKey& pk):m_pk(pk){
	// ...
}

/*
The original implementation is not secure (See Guan et al.'s paper in header file <she.h>).
*/

/*
void SHE::Encryptor::encrypt(const HEnc::PTxt& pt, HEnc::CTxt& ct){
	NTL::ZZ m, r, c;
	r = NTL::RandomLen_ZZ(m_pk.get_k2()); 
	
	m = pt.get_pt();
	if( m > 0 ){
		c = (r*m_pk.get_enc0() + m*m_pk.get_enc1()) % m_pk.get_N();
	}
	else if ( m < 0 ){
		c = (r*m_pk.get_enc0() + m*m_pk.get_encn1()) % m_pk.get_N();
	}
	else{
		c = (r*m_pk.get_enc0()) % m_pk.get_N();
	}
	
	ct.set_ct(c);
}*/

void SHE::Encryptor::encrypt(const HEnc::PTxt& pt, HEnc::CTxt& ct){
	NTL::ZZ m, r1, r2, c;
	
	r1 = NTL::RandomLen_ZZ(m_pk.get_k2()); 
	r2 = NTL::RandomLen_ZZ(m_pk.get_k2()); 
	m = pt.get_pt();
	
	if( m > 0 ){
		c = (r1*m_pk.get_enc01() + r2*m_pk.get_enc02() + m*m_pk.get_enc1()) % m_pk.get_N();
	}
	else if ( m < 0 ){
		c = (r1*m_pk.get_enc01() + r2*m_pk.get_enc02() + m*m_pk.get_encn1()) % m_pk.get_N();
	}
	else{
		c = (r1*m_pk.get_enc01() + r2*m_pk.get_enc02()) % m_pk.get_N();
	}
	
	ct.set_ct(c);
}
		
void SHE::Encryptor::he_add(const HEnc::CTxt& ct1, const HEnc::CTxt& ct2, HEnc::CTxt& ct){
	NTL::ZZ c1, c2, r, c;
	
	c1 = ct1.get_ct();
	c2 = ct2.get_ct();
	
	r = NTL::RandomLen_ZZ(m_pk.get_k2() - 1);
	//c = (r*m_pk.get_enc0()) % m_pk.get_N();
	c = (r*m_pk.get_enc01()) % m_pk.get_N();
	
	c = (c + c1 + c2) % m_pk.get_N();
	
	ct.set_ct(c);
}

void SHE::Encryptor::he_add(const HEnc::CTxt& ct1, const HEnc::PTxt& pt1, HEnc::CTxt& ct){
	NTL::ZZ c1, m1, r, c;
	
	c1 = ct1.get_ct();
	m1 = pt1.get_pt();
	
	r = NTL::RandomLen_ZZ(m_pk.get_k2() - 1);
	//c = (r*m_pk.get_enc0()) % m_pk.get_N();
	c = (r*m_pk.get_enc01()) % m_pk.get_N();
	
	c = (c + c1 + m1) % m_pk.get_N();
	
	ct.set_ct(c);
}

void SHE::Encryptor::he_add(const HEnc::PTxt& pt1, const HEnc::CTxt& ct1, HEnc::CTxt& ct){
	this->he_add(ct1, pt1, ct);
}
		
void SHE::Encryptor::he_mul(const HEnc::CTxt& ct1, const HEnc::PTxt& pt1, HEnc::CTxt& ct){
	NTL::ZZ c1, m1, r, c;
	
	c1 = ct1.get_ct();
	m1 = pt1.get_pt();
	
	r = NTL::RandomLen_ZZ(m_pk.get_k2() - 1);
	
	//c = (r*m_pk.get_enc0()) % m_pk.get_N();
	c = (r*m_pk.get_enc01()) % m_pk.get_N();
	c = (c + c1 * m1) % m_pk.get_N();
	//c = (c1 * m1) % m_pk.get_N();
	
	ct.set_ct(c);
}

void SHE::Encryptor::he_mul(const HEnc::PTxt& pt1, const HEnc::CTxt& ct1, HEnc::CTxt& ct){
	this->he_mul(ct1, pt1, ct);
}

void SHE::Encryptor::he_mul(const HEnc::CTxt& ct1, const HEnc::CTxt& ct2, HEnc::CTxt& ct){
	NTL::ZZ c1, c2, r, c;
	
	c1 = ct1.get_ct();
	c2 = ct2.get_ct();
	
	r = NTL::RandomLen_ZZ(m_pk.get_k2() - 1);
	
	//c = (r*m_pk.get_enc0()) % m_pk.get_N();
	c = (r*m_pk.get_enc01()) % m_pk.get_N();
	c = (c + c1 * c2) % m_pk.get_N();
	
	ct.set_ct(c);
}

SHE::Decryptor::Decryptor(const SecretKey& sk):m_sk(sk){
	// ...
}

void SHE::Decryptor::decrypt(const HEnc::CTxt& ct, HEnc::PTxt& pt){
	NTL::ZZ c, t, m;
	
	c = ct.get_ct();
	
	t = (c % m_sk.get_p()) % m_sk.get_L();
	
	if( t < (m_sk.get_L() / 2)){
		m = t;
	}
	else{
		m = t - m_sk.get_L();
	}
	pt.set_pt(m);
}

/*
void SHE::key_gen(SecretKey& sk, PublicKey& pk, long k0, long k1, long k2){
	if ( k2 >= k0 / 2){ // throw an exception
		throw std::invalid_argument("invalid_argument: k0 > 2*k2");
	}
	
	// Generate random values p and q
	NTL::ZZ p, q, N;
	p =  NTL::GenPrime_ZZ(k0, 80);
	q =  NTL::GenPrime_ZZ(k0, 80);
	N= p*q;
	
	NTL::ZZ L;
	L = NTL::GenPrime_ZZ(k2, 80);
	
	// Generate the ciphertexts of messages 0, 1, and -1
	NTL::ZZ e0, e1, en1;
	NTL::ZZ rl, rp;
	
	rl = NTL::RandomLen_ZZ(k2);
	rp = NTL::RandomLen_ZZ(k0);
	e0 = ((rl*L + 0) * (1 + rp*p)) % N;	

	rl = NTL::RandomLen_ZZ(k2);
	rp = NTL::RandomLen_ZZ(k0);
	e1 = ((rl*L + 1) * (1 + rp*p)) % N;
	
	rl = NTL::RandomLen_ZZ(k2);
	rp = NTL::RandomLen_ZZ(k0);
	en1 = ((rl*L - 1) * (1 + rp*p)) % N;
	
	SecretKey prikey(p, q, L);
	PublicKey pubkey(N, e0, e1, en1, k0, k1, k2);
	
	sk = prikey;
	pk = pubkey;
}*/

void SHE::key_gen(SecretKey& sk, PublicKey& pk, long k0, long k1, long k2){
	if ( k2 >= k0 / 2){ // throw an exception
		throw std::invalid_argument("invalid_argument: k0 > 2*k2");
	}
	
	// Generate random values p and q
	NTL::ZZ p, q, N;
	p =  NTL::GenPrime_ZZ(k0, 80);
	q =  NTL::GenPrime_ZZ(k0, 80);
	N= p*q;
	
	NTL::ZZ L;
	L = NTL::GenPrime_ZZ(k2, 80);
	
	// Generate the ciphertexts of messages 0, 1, and -1
	NTL::ZZ e01, e02, e1, en1;
	NTL::ZZ rl, rp;
	
	rl = NTL::RandomLen_ZZ(k2);
	rp = NTL::RandomLen_ZZ(k0);
	e01 = ((rl*L + 0) * (1 + rp*p)) % N;	

	rl = NTL::RandomLen_ZZ(k2);
	rp = NTL::RandomLen_ZZ(k0);
	e02 = ((rl*L + 0) * (1 + rp*p)) % N;

	rl = NTL::RandomLen_ZZ(k2);
	rp = NTL::RandomLen_ZZ(k0);
	e1 = ((rl*L + 1) * (1 + rp*p)) % N;
	
	rl = NTL::RandomLen_ZZ(k2);
	rp = NTL::RandomLen_ZZ(k0);
	en1 = ((rl*L - 1) * (1 + rp*p)) % N;
	
	SecretKey prikey(p, q, L);
	PublicKey pubkey(N, e01, e02, e1, en1, k0, k1, k2);
	
	sk = prikey;
	pk = pubkey;
}
