/*
 * This is written by Lulu Han.
 * E-mail: locomotive_crypto@163.com
 */

#ifndef HEENC_HENC_H
#define HEENC_HENC_H

#include <NTL/ZZ.h>

class HEnc{
public:
	class PTxt{
	public:
		void set_pt(const NTL::ZZ& pt);
		NTL::ZZ get_pt() const;
	private:
		NTL::ZZ m_pt;
	};
	
	class CTxt{
	public:
		void set_ct(const NTL::ZZ& ct);
		NTL::ZZ get_ct() const;
		
		void set_ct1(const NTL::ZZ& ct1);
		void set_ct2(const NTL::ZZ& ct2);
		NTL::ZZ get_ct1() const;
		NTL::ZZ get_ct2() const;
	private:
		NTL::ZZ m_ct;
		NTL::ZZ m_ct1;
		NTL::ZZ m_ct2;
	};
	
	class Encryptor{
	public:
		virtual void encrypt(const HEnc::PTxt& pt, HEnc::CTxt& ct);
		
		virtual void he_add(const HEnc::CTxt& ct1, const HEnc::CTxt& ct2, HEnc::CTxt& ct);
		virtual void he_add(const HEnc::CTxt& ct1, const HEnc::PTxt& pt1, HEnc::CTxt& ct);
		virtual void he_add(const HEnc::PTxt& pt1, const HEnc::CTxt& ct1, HEnc::CTxt& ct);
		
		virtual void he_mul(const HEnc::CTxt& ct1, const HEnc::PTxt& pt1, HEnc::CTxt& ct);
		virtual void he_mul(const HEnc::PTxt& pt1, const HEnc::CTxt& ct1, HEnc::CTxt& ct);
		virtual void he_mul(const HEnc::CTxt& ct1, const HEnc::CTxt& ct2, HEnc::CTxt& ct);
		virtual ~Encryptor();
	}; 

	class Decryptor{
	public:
		virtual void decrypt(const HEnc::CTxt& ct, HEnc::PTxt& pt);
		virtual ~Decryptor();
	};
};

#endif // HEENC_HENC_H

