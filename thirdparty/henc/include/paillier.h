/*
 * This is written by Lulu Han.
 * E-mail: locomotive_crypto@163.com
 */
 
/*Reference:
@inproceedings{paillier1999public,
  title={Public-key cryptosystems based on composite degree residuosity classes},
  author={Paillier, Pascal},
  booktitle={International conference on the theory and applications of cryptographic techniques},
  pages={223--238},
  year={1999},
  organization={Springer}
}
 */ 
 
#ifndef HEENC_PAILLIER_H
#define HEENC_PAILLIER_H

#include <NTL/ZZ.h>
#include "henc.h"

class Paillier{
public:

	class SecretKey{
	public:
		SecretKey(){}
		SecretKey(const NTL::ZZ& p, const NTL::ZZ& q);
		NTL::ZZ get_phi_N();
		NTL::ZZ get_phi_N_inv();
		NTL::ZZ get_N();
		NTL::ZZ get_N_square();
	private:
		NTL::ZZ phi_N;
		NTL::ZZ phi_N_inv;
		NTL::ZZ N; //N = p*q
		NTL::ZZ N_square; 
	};
	
	class PublicKey{
	public:
		PublicKey(){}
		PublicKey(const NTL::ZZ& N);
		NTL::ZZ get_N();
		NTL::ZZ get_G();
		NTL::ZZ get_N_square();
	private:
		NTL::ZZ G;
		NTL::ZZ N;
		NTL::ZZ N_square;
	};
	
	class Encryptor: public HEnc::Encryptor{
	public:
		Encryptor(const PublicKey& pk);
		
		void encrypt(const HEnc::PTxt& pt, HEnc::CTxt& ct) override;
		void he_sub(const HEnc::CTxt& ct1, const HEnc::CTxt& ct2, HEnc::CTxt& ct);
		virtual void he_add(const HEnc::CTxt& ct1, const HEnc::CTxt& ct2, HEnc::CTxt& ct) override;
		virtual void he_add(const HEnc::CTxt& ct1, const HEnc::PTxt& pt1, HEnc::CTxt& ct) override;
		virtual void he_add(const HEnc::PTxt& pt1, const HEnc::CTxt& ct1, HEnc::CTxt& ct) override;
		
		virtual void he_mul(const HEnc::CTxt& ct1, const HEnc::PTxt& pt1, HEnc::CTxt& ct) override;
		virtual void he_mul(const HEnc::PTxt& pt1, const HEnc::CTxt& ct1, HEnc::CTxt& ct) override;
		
	private:
		PublicKey m_pk;
	};
	
	class Decryptor: public HEnc::Decryptor{
	public:
		Decryptor(const SecretKey& sk);
		
		void decrypt(const HEnc::CTxt& ct, HEnc::PTxt& pt) override;
	private:
		SecretKey m_sk;
	};
	
	// Generate a random key pair
	static void key_gen(SecretKey& sk, PublicKey& pk, long bitlens);
	static void key_gen(SecretKey& sk, PublicKey& pk, long bitlens, NTL::ZZ& p, NTL::ZZ& q);
	static void key_load(SecretKey& sk, PublicKey& pk,  NTL::ZZ& p, NTL::ZZ& q);
};

#endif // HEENC_PAILLIER_H
