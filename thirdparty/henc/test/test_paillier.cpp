/*
 * This is written by Lulu Han.
 * E-mail: locomotive_crypto@163.com
 */

#include <iostream>
#include <exception>
#include <boost/program_options.hpp>
#include "paillier.h"
#include <chrono>

namespace op = boost::program_options;

void test_paillier_for_correctness(long bitlens);

int main(int argc, char* argv[]){
	long bitlens;
	op::options_description desc("All options for testing Paillier algorithm");
	desc.add_options()
		("help", "Produce help message")
		("bitlens", op::value<long>(&bitlens)->default_value(100), "Key length");
	
	op::variables_map vm;
	op::store(op::parse_command_line(argc, argv, desc), vm);
	op::notify(vm);
	
	if(argc == 1 || vm.count("help")){
		std::cout << desc << std::endl;
		return 0;
	}
		
	if(vm.count("bitlens")){
		test_paillier_for_correctness(bitlens);
		return 0;
	}
	return 0;
}


void test_paillier_for_correctness(long bitlens){
	std::cout << "The key length is: " << 2*bitlens << " (bits)" << std::endl;
	
	Paillier::SecretKey sk;
	Paillier::PublicKey pk;
	Paillier::key_gen(sk, pk, bitlens);
	
	Paillier::Encryptor enc(pk);
	Paillier::Decryptor dec(sk);
	
	NTL::ZZ m;
	m = 2;
	
	HEnc::PTxt pt, pt2;
	HEnc::CTxt ct, ct2;
	pt2.set_pt(m);
	pt.set_pt(m);
	std::cout << "pt = " << pt.get_pt() << std::endl;
	auto start = std::chrono::high_resolution_clock::now();\
	for (int i = 0; i < 1; i++) {
		// Encrypt a message pt
		enc.encrypt(pt, ct);
		enc.encrypt(pt2, ct2);
		enc.he_sub(ct, ct2, ct);
		std::cout << "ct = " << ct.get_ct() << std::endl;
		
		// Decrypt a message ct
		HEnc::PTxt rt;
		dec.decrypt(ct, rt);
		std::cout << "rt(m) = " << rt.get_pt() << std::endl;
	}
	

	auto finish = std::chrono::high_resolution_clock::now();

	
    // std::cout << "finish 1000 times encrypt/decrypt using time: " << std::chrono::duration_cast<std::chrono::milliseconds>(finish - start).count() << " ms" << std::endl;
	
	/*
	if(rt.get_pt() != pt.get_pt()){
		throw std::runtime_error("Testing encrypt() and decrypt() functions failed...");
	}
	
	// Testing for homomorphic addition
	// 1) Homomorphic addition for two ciphertexts
	std::cout << "\nHomomorphic addition for two ciphertexts..." << std::endl;
	NTL::ZZ m2;
	m2 = NTL::RandomLen_ZZ(32);
	
	HEnc::PTxt pt2;
	pt2.set_pt(m2);
	std::cout << "\npt2 = " << pt2.get_pt() << std::endl;
	
	HEnc::CTxt ct2;
	enc.encrypt(pt2, ct2);
	
	enc.he_add(ct, ct2, ct);
	std::cout << "ct = " << ct.get_ct() << std::endl;
	
	dec.decrypt(ct, rt);
	std::cout << "rt(pt + pt2) = " << rt.get_pt() << std::endl;
	
	if(rt.get_pt() != (pt.get_pt() + pt2.get_pt())){
		throw std::runtime_error("Testing he_add() functions failed...");
	}
	
	// 2) Homomorphic addition for one ciphertext and one plaintext
	std::cout << "\nHomomorphic addition for one ciphertext and one plaintext..." << std::endl;
	NTL::ZZ m3;
	m3 = NTL::RandomLen_ZZ(32);
	HEnc::PTxt pt3;
	pt3.set_pt(m3);
	std::cout << "\npt3 = " << pt3.get_pt() << std::endl;
	
	enc.he_add(ct2, pt3, ct);
	std::cout << "ct = " << ct.get_ct() << std::endl;
	
	dec.decrypt(ct, rt);
	std::cout << "rt(pt2 + pt3) = " << rt.get_pt() << std::endl;
	
	if(rt.get_pt() != (pt2.get_pt() + pt3.get_pt())){
		throw std::runtime_error("Testing he_add() functions failed...");
	}
	
	// 3) Homomorphic multiplication for one ciphertext and one plaintext
	std::cout << "\nHomomorphic multiplication for one ciphertext and one plaintext..." << std::endl;
	NTL::ZZ m4;
	m4 = NTL::RandomLen_ZZ(32);
	HEnc::PTxt pt4;
	pt4.set_pt(m4);
	std::cout << "\npt4 = " << pt4.get_pt() << std::endl;
	
	enc.he_mul(ct2, pt4, ct);
	std::cout << "ct = " << ct.get_ct() << std::endl;
	
	dec.decrypt(ct, rt);
	std::cout << "rt(pt2 * pt4) = " << rt.get_pt() << std::endl;
	
	if(rt.get_pt() != (pt2.get_pt() * pt4.get_pt())){
		throw std::runtime_error("Testing he_mul() functions failed...");
	}
	*/
}
