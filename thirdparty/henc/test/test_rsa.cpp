/*
 * This is written by Lulu Han.
 * E-mail: locomotive_crypto@163.com
 */

#include <iostream>
#include <exception>
#include <boost/program_options.hpp>
#include "rsa.h"

namespace op = boost::program_options;

void test_rsa_for_correctness(long pqbitlens);

int main(int argc, char* argv[]){
	
	long pqbitlens;
	op::options_description desc("All options for testing RSA algorithm");
	desc.add_options()
		("help", "Produce help message")
		("pqbitlens", op::value<long>(&pqbitlens)->default_value(100), "Key length");
	
	op::variables_map vm;
	op::store(op::parse_command_line(argc, argv, desc), vm);
	op::notify(vm);
	
	if(argc == 1 || vm.count("help")){
		std::cout << desc << std::endl;
		return 0;
	}
		
	if(vm.count("pqbitlens")){
		test_rsa_for_correctness(pqbitlens);
		return 0;
	}
	
	
	return 0;
}


void test_rsa_for_correctness(long pqbitlens){
	RSA::SecretKey sk;
	RSA::PublicKey pk;
	RSA::key_gen(sk, pk, pqbitlens);
	
	RSA::Encryptor enc(pk);
	RSA::Decryptor dec(sk);
	
	NTL::ZZ m;
	m = NTL::RandomLen_ZZ(32);
	
	HEnc::PTxt pt;
	HEnc::CTxt ct;
	
	pt.set_pt(m);
	std::cout << "pt(m) = " << pt.get_pt() << std::endl;
	
	// Encrypt a message pt
	enc.encrypt(pt, ct);
	std::cout << "ct(m): " << ct.get_ct() << std::endl;
	
	// Decrypt a message ct
	HEnc::PTxt rt;
	dec.decrypt(ct, rt);
	std::cout << "rt(m) = " << rt.get_pt() << std::endl;
	
	if(rt.get_pt() != pt.get_pt()){
		throw std::runtime_error("Testing encrypt() and decrypt() functions failed...");
	}
	
	// Testing for homomorphic multiplication
	// 1) Homomorphic multiplication for two ciphertexts
	std::cout << "\nHomomorphic multiplication for two ciphertexts..." << std::endl;
	NTL::ZZ m2;
	m2 = NTL::RandomLen_ZZ(32);
	
	HEnc::PTxt pt2;
	pt2.set_pt(m2);
	std::cout << "pt2 = " << pt2.get_pt() << std::endl;
	
	HEnc::CTxt ct2;
	enc.encrypt(pt2, ct2);
	
	enc.he_mul(ct, ct2, ct);
	std::cout << "ct(pt * pt2): " << ct.get_ct() << std::endl;
	
	dec.decrypt(ct, rt);
	std::cout << "rt(ct * ct2) = " << rt.get_pt() << std::endl;
	
	if(rt.get_pt() != (pt.get_pt() * pt2.get_pt())){
		throw std::runtime_error("Testing he_mul() functions failed...");
	}
	
	// 2) Homomorphic multiplication for one ciphertext and one plaintext
	std::cout << "\nHomomorphic multiplication for one ciphertext and one plaintext..." << std::endl;
	NTL::ZZ m3;
	m3 = NTL::RandomLen_ZZ(32);
	
	HEnc::PTxt pt3;
	pt3.set_pt(m3);
	std::cout << "pt3 = " << pt3.get_pt() << std::endl;
	
	enc.he_mul(ct2, pt3, ct);
	std::cout << "ct(ct2 * pt3): " << ct.get_ct() << std::endl;
	
	dec.decrypt(ct, rt);
	std::cout << "rt(pt2 * pt3) = " << rt.get_pt() << std::endl;
	
	if(rt.get_pt() != (pt2.get_pt() * pt3.get_pt())){
		throw std::runtime_error("Testing he_mul() functions failed...");
	}
}
