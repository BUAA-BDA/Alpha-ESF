/*
 * This is written by Lulu Han.
 * E-mail: locomotive_crypto@163.com
 */

#ifndef HEENC_RSA_H
#define HEENC_RSA_H

#include <NTL/ZZ.h>
#include "henc.h"

class RSA{
public:
	class SecretKey{
	public:
		SecretKey(){}
		SecretKey(const NTL::ZZ& d, const NTL::ZZ& N);
		
		NTL::ZZ get_d();
		NTL::ZZ get_N();
		
	private:
		NTL::ZZ m_d;
		NTL::ZZ m_N;
	};
	
	class PublicKey{
	public:
		PublicKey(){}
		PublicKey(const NTL::ZZ& e, const NTL::ZZ& N);
		
		NTL::ZZ get_e();
		NTL::ZZ get_N();
	private:
		NTL::ZZ m_e;
		NTL::ZZ m_N;
	};
	
	class Encryptor: public HEnc::Encryptor{
	public:
		Encryptor(const PublicKey& pk);
	
		virtual void encrypt(const HEnc::PTxt& pt, HEnc::CTxt& ct) override;
		
		virtual void he_mul(const HEnc::CTxt& ct1, const HEnc::PTxt& pt1, HEnc::CTxt& ct) override;
		virtual void he_mul(const HEnc::PTxt& pt1, const HEnc::CTxt& ct1, HEnc::CTxt& ct) override;
		virtual void he_mul(const HEnc::CTxt& ct1, const HEnc::CTxt& ct2, HEnc::CTxt& ct) override;
	private:
		PublicKey m_pk;
	};
	
	class Decryptor: public HEnc::Decryptor{
	public:
		Decryptor(const SecretKey& sk);
		
		virtual void decrypt(const HEnc::CTxt& ct, HEnc::PTxt& pt) override;
	private:
		SecretKey m_sk;
	};
	
	// Generate a random key pair
	static void key_gen(SecretKey& sk, PublicKey& pk, long pqbitlens);
};

#endif // HEENC_RSA_H
