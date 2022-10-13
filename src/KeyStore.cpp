#include "KeyStore.h"

KeyStore::KeyStore() {}

KeyStore::KeyStore(ZZ &p, ZZ &q)
{
    long lbits = NTL::NumBits(p);
    this->p_n_bytes = (lbits + 7) / 8;
    this->p_char_list = vector<unsigned char>(this->p_n_bytes);
    NTL::BytesFromZZ(&(this->p_char_list[0]), p, this->p_n_bytes);
    lbits = NTL::NumBits(q);
    this->q_n_bytes = (lbits + 7) / 8;
    this->q_char_list = vector<unsigned char>(this->q_n_bytes);
    NTL::BytesFromZZ(&(this->q_char_list[0]), q, this->q_n_bytes);
}

void KeyStore::load(ZZ &p, ZZ &q)
{
    NTL::ZZFromBytes(p, &(this->p_char_list[0]), this->p_n_bytes);
    NTL::ZZFromBytes(q, &(this->q_char_list[0]), this->q_n_bytes);
}