/*
 * This is written by Lulu Han and Yunguo Guan.
 * E-mail: locomotive_crypto@163.com
 */

#include <iostream>
#include <exception>
#include <boost/program_options.hpp>
#include "she.h"

namespace op = boost::program_options;

void test_she_for_correctness(long k0, long k1, long k2);

int main(int argc, char* argv[]){
	op::options_description desc("All options for testing SHE algorithm");
	desc.add_options()
		("help", "Produce help message")
		("k0", op::value<long>(), "The length of p and q")
		("k1", op::value<long>(), "The spave size of message")
		("k2", op::value<long>(), "The security level");
	
	op::variables_map vm;
	op::store(op::parse_command_line(argc, argv, desc), vm);
	op::notify(vm);
	
	if(argc == 1 || vm.count("help")){
		std::cout << desc << std::endl;
		return 0;
	}
		
	if(vm.count("k0") && vm.count("k1") && vm.count("k2")){
		test_she_for_correctness(
			vm["k0"].as<long>(), 
				vm["k1"].as<long>(),
					vm["k2"].as<long>());
		return 0;
	}
	return 0;
}


void test_she_for_correctness(long k0, long k1, long k2){
	long msg_len = 20;
	SHE::SecretKey sk;
	SHE::PublicKey pk;
	
	SHE::key_gen(sk, pk, k0, k1, k2);
	
	SHE::Encryptor enc(pk);
	SHE::Decryptor dec(sk);
	
	NTL::ZZ m;
	m = NTL::RandomLen_ZZ(msg_len);
	
	HEnc::PTxt pt;
	HEnc::CTxt ct;
	
	std::cout << "Testing for encryption and decryption..." << std::endl;
	
	pt.set_pt(m);
	std::cout << "pt = " << pt.get_pt() << std::endl;
	
	// Encrypt a message pt
	enc.encrypt(pt, ct);
	std::cout << "ct(pt) = " << ct.get_ct() << std::endl;
	
	// Decrypt a message ct
	HEnc::PTxt rt;
	dec.decrypt(ct, rt);
	std::cout << "recover(pt) = " << rt.get_pt() << std::endl;
	
	// Testing for homomorphic addition
	std::cout << "\n1) Homomorphic addition for two ciphertexts..." << std::endl;
	NTL::ZZ m2;
	m2 = NTL::RandomLen_ZZ(msg_len);
	
	HEnc::PTxt pt2;
	pt2.set_pt(m2);
	std::cout << "pt2 = " << pt2.get_pt() << std::endl;
	
	HEnc::CTxt ct2;
	enc.encrypt(pt2, ct2);
	std::cout << "ct2(pt2) = " << ct2.get_ct() << std::endl;
	
	enc.he_add(ct, ct2, ct);
	std::cout << "ct(pt + pt2) = " << ct.get_ct() << std::endl;
	
	dec.decrypt(ct, rt);
	std::cout << "recover(pt + pt2) = " << rt.get_pt() << std::endl;
	
	if(rt.get_pt() != (pt.get_pt() + pt2.get_pt())){
		throw std::runtime_error("Testing he_add() functions failed...");
	}
	
	std::cout << "\n2) Homomorphic addition for one ciphertext and one plaintext..." << std::endl;
	NTL::ZZ m3;
	m3 = NTL::RandomLen_ZZ(msg_len);
	
	HEnc::PTxt pt3;
	pt3.set_pt(m3);
	
	std::cout << "pt3 = " << pt3.get_pt() << std::endl;
	
	enc.he_add(ct2, pt3, ct);
	std::cout << "ct(pt2 + pt3) = " << ct.get_ct() << std::endl;
	
	dec.decrypt(ct, rt);
	std::cout << "recover(pt2 + pt3) = " << rt.get_pt() << std::endl;
	
	if(rt.get_pt() != (pt2.get_pt() + pt3.get_pt())){
		throw std::runtime_error("Testing he_add() functions failed...");
	}
	
	std::cout << "\n3) Homomorphic multiplication for one ciphertext and one plaintext..." << std::endl;
	NTL::ZZ m4;
	m4 = NTL::RandomLen_ZZ(msg_len);
	
	HEnc::PTxt pt4;
	pt4.set_pt(m4);
	
	std::cout << "pt4 = " << pt4.get_pt() << std::endl;
	
	enc.he_mul(ct2, pt4, ct);
	std::cout << "ct(pt2 * pt4) = " << ct.get_ct() << std::endl;
	
	dec.decrypt(ct, rt);
	std::cout << "recover(pt2 * pt4) = " << rt.get_pt() << std::endl;
	
	if(rt.get_pt() != (pt2.get_pt() * pt4.get_pt())){
		throw std::runtime_error("Testing he_mul() functions failed...");
	}
	
	// Testing for homomorphic multiplication
	std::cout << "\n4) Homomorphic multiplication for one ciphertext and one ciphertext..." << std::endl;
	HEnc::CTxt ct4;
	
	enc.encrypt(pt4, ct4);
	std::cout << "ct(pt4) = " << ct4.get_ct() << std::endl;
	
	enc.he_mul(ct2, ct4, ct);
	std::cout << "ct(pt2 * pt4) = " << ct.get_ct() << std::endl;
	
	dec.decrypt(ct, rt);
	std::cout << "recover(pt2 * pt4) = " << rt.get_pt() << std::endl;
	
	if(rt.get_pt() != (pt2.get_pt() * pt4.get_pt())){
		throw std::runtime_error("Testing he_mul() functions failed...");
	}
}
