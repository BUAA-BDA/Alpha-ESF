/*
 * This is written by Lulu Han.
 * E-mail: locomotive_crypto@163.com
 */
 
#include <exception>
#include "henc.h"

void HEnc::PTxt::set_pt(const NTL::ZZ& pt){
	m_pt = pt;
}

NTL::ZZ HEnc::PTxt::get_pt() const{
	return m_pt;
}


void HEnc::CTxt::set_ct(const NTL::ZZ& ct){
	m_ct = ct;
}

NTL::ZZ HEnc::CTxt::get_ct() const{
	return m_ct;
}

void HEnc::CTxt::set_ct1(const NTL::ZZ& ct1){
	m_ct1 = ct1;
}

void HEnc::CTxt::set_ct2(const NTL::ZZ& ct2){
	m_ct2 = ct2;
}

NTL::ZZ HEnc::CTxt::get_ct1() const{
	return m_ct1;
}

NTL::ZZ HEnc::CTxt::get_ct2() const{
	return m_ct2;
}

HEnc::Decryptor::~Decryptor(){
	// ...
}

void HEnc::Encryptor::encrypt(const PTxt& c, CTxt& m){
	throw std::runtime_error("The function encrypt(pt, ct) is not implemented...");
}

void HEnc::Encryptor::he_add(const CTxt& ct1, const CTxt& ct2, CTxt& ct){
	throw std::runtime_error("The function he_add(ct, ct, ct) is not implemented...");
}

void HEnc::Encryptor::he_add(const CTxt& ct1, const PTxt& pt1, CTxt& ct){
	throw std::runtime_error("The function he_add(ct, pt, ct) is not implemented...");
}

void HEnc::Encryptor::he_add(const PTxt& ct1, const CTxt& pt1, CTxt& ct){
	throw std::runtime_error("The function he_add(ct, pt, ct) is not implemented...");
}

void HEnc::Encryptor::he_mul(const CTxt& ct1, const PTxt& pt1, CTxt& ct){
	throw std::runtime_error("The function he_mul(ct, pt, ct) is not implemented...");
}

void HEnc::Encryptor::he_mul(const PTxt& ct1, const CTxt& pt1, CTxt& ct){
	throw std::runtime_error("The function he_mul(pt, ct, ct) is not implemented...");
}

void HEnc::Encryptor::he_mul(const CTxt& ct1, const CTxt& ct2, CTxt& ct){
	throw std::runtime_error("The function he_mul(ct, ct, ct) is not implemented...");
}

HEnc::Encryptor::~Encryptor(){
	// ...
}

void HEnc::Decryptor::decrypt(const CTxt& m, PTxt& c){
	throw std::runtime_error("The function decrypt() is not implemented...");
}

