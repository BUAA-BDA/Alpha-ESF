/*
 * This is written by Lulu Han.
 * E-mail: locomotive_crypto@163.com
 */

/*@article{elgamal1985public,
  title={A public key cryptosystem and a signature scheme based on discrete logarithms},
  author={ElGamal, Taher},
  journal={IEEE transactions on information theory},
  volume={31},
  number={4},
  pages={469--472},
  year={1985},
  publisher={IEEE}
}
*/

#ifndef HEENC_ELGAMAL_H
#define HEENC_ELGAMAL_H

#include <NTL/ZZ.h>
#include "henc.h"

class Elgamal{
public:
	class SecretKey{
	public:
		SecretKey(){}
		SecretKey(const NTL::ZZ& p, const NTL::ZZ& g, const NTL::ZZ& sk);
		
		NTL::ZZ get_P() const;
		NTL::ZZ get_G() const;
		NTL::ZZ get_sk() const;
	private:
		NTL::ZZ m_p;
		NTL::ZZ m_g;
		NTL::ZZ m_sk;
	};
	
	class PublicKey{
	public:
		PublicKey(){}
		PublicKey(const NTL::ZZ& p, const NTL::ZZ& g, const NTL::ZZ& pk);
		
		NTL::ZZ get_P() const;
		NTL::ZZ get_G() const;
		NTL::ZZ get_pk() const;
	private:
		NTL::ZZ m_p;
		NTL::ZZ m_g;
		NTL::ZZ m_pk;
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
	
	// Generate random key pair
	static void key_gen(SecretKey& sk, PublicKey& pk, long mod_bitlens, long group_bitlens);
};

#endif // HEENC_ELGAMAL_H
