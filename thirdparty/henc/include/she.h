/*
 * This is written by Lulu Han and Yunguo Guan.
 * E-mail: locomotive_crypto@163.com
 * 
References:
@article{mahdikhani2020achieving,
  title={Achieving O (log$^3$n) communication-efficient privacy-preserving range query in fog-based IoT},
  author={Mahdikhani, Hassan and Lu, Rongxing and Zheng, Yandong and Shao, Jun and Ghorbani, Ali A},
  journal={IEEE Internet of Things Journal},
  volume={7},
  number={6},
  pages={5220--5232},
  year={2020},
  publisher={IEEE}
}

@article{guan2021toward,
  title={Toward Privacy-Preserving Cybertwin-Based Spatiotemporal Keyword Query for ITS in 6G Era},
  author={Guan, Yunguo and Lu, Rongxing and Zheng, Yandong and Zhang, Songnian and Shao, Jun and Wei, Guiyi},
  journal={IEEE Internet of Things Journal},
  volume={8},
  number={22},
  pages={16243--16255},
  year={2021},
  publisher={IEEE}
}

@article{zheng2021efficient,
  title={Efficient and privacy-preserving similarity range query over encrypted time series data},
  author={Zheng, Yandong and Lu, Rongxing and Guan, Yunguo and Shao, Jun and Zhu, Hui},
  journal={IEEE Transactions on Dependable and Secure Computing},
  year={2021},
  publisher={IEEE}
}
 */


#ifndef HEENC_SHE_H
#define HEENC_SHE_H

#include  <NTL/ZZ.h>
#include "henc.h"

class SHE{
public:
	
	class SecretKey{
	public:
		SecretKey(){}
		SecretKey(const NTL::ZZ& p, const NTL::ZZ& q, const NTL::ZZ& L);
		
		NTL::ZZ get_N() const;
		NTL::ZZ get_p() const;
		NTL::ZZ get_q() const;
		NTL::ZZ get_L() const;
	
	private:
		NTL::ZZ m_N;
		NTL::ZZ m_p;
		NTL::ZZ m_q;
		NTL::ZZ m_L;
	};


	class PublicKey{
	public:
		PublicKey(){}
		/*
		 * Note that e0 is the encryption of plaintext 0, 
		 * 		e1 is the encryption of plaintext 1,
		 * 		en1 is the encryption of -1.
		 */ 
		//PublicKey(const NTL::ZZ& N, const NTL::ZZ& e0, const NTL::ZZ& e1, 
		//	const NTL::ZZ& en1, long k0, long k1, long k2);
		
		PublicKey(const NTL::ZZ& N, const NTL::ZZ& e01, const NTL::ZZ& e02, const NTL::ZZ& e1, 
			const NTL::ZZ& en1, long k0, long k1, long k2);
		
		NTL::ZZ get_N() const;
		long get_k2() const;
		long get_k1() const;
		long get_mul_depth() const;
		
		//NTL::ZZ get_enc0() const;
		NTL::ZZ get_enc01() const;
		NTL::ZZ get_enc02() const;
		NTL::ZZ get_enc1() const;
		NTL::ZZ get_encn1() const;
	private:
		NTL::ZZ m_N;
		//NTL::ZZ m_enc_0;
		NTL::ZZ m_enc_01;
		NTL::ZZ m_enc_02;
		NTL::ZZ m_enc_1;
		NTL::ZZ m_enc_neg_1;
		long m_k0, m_k1, m_k2;
	};

	class Encryptor: public HEnc::Encryptor{
	public:
		Encryptor(const PublicKey& pk);
		
		void encrypt(const HEnc::PTxt& pt, HEnc::CTxt& ct) override;
		
		virtual void he_add(const HEnc::CTxt& ct1, const HEnc::CTxt& ct2, HEnc::CTxt& ct) override;
		virtual void he_add(const HEnc::CTxt& ct1, const HEnc::PTxt& pt1, HEnc::CTxt& ct) override;
		virtual void he_add(const HEnc::PTxt& pt1, const HEnc::CTxt& ct1, HEnc::CTxt& ct) override;
		
		virtual void he_mul(const HEnc::CTxt& ct1, const HEnc::PTxt& pt1, HEnc::CTxt& ct) override;
		virtual void he_mul(const HEnc::PTxt& pt1, const HEnc::CTxt& ct1, HEnc::CTxt& ct) override;
		virtual void he_mul(const HEnc::CTxt& ct1, const HEnc::CTxt& ct2, HEnc::CTxt& ct) override;
		
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
	static void key_gen(SecretKey& sk, PublicKey& pk, long k0, long k1, long k2);
};

#endif // HEENC_SHE_H
