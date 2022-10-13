#include "HashFunctions.h"

#ifndef ENC_SUM_FILTER
#define ENC_SUM_FILTER

class EncSumFilter
{
private:
    friend class boost::serialization::access;

    template <class Archive>
    void serialize(Archive &ar, const unsigned int version)
    {
        ar & bloom;
        ar & byte_length;
        ar & m;
        ar & pad;
        ar & hash_function;
    }

public:
    vector<unsigned char> bloom;
    vector<int> byte_length;
    unordered_map<int, ZZ> cipher_bloom;
    int m;
    int64_t pad;
    HashFunctions hash_function;

    EncSumFilter();
    EncSumFilter(int m, vector<raw_data> *data, Paillier::Encryptor &enc);
    EncSumFilter(Channel &chl, int m);
    void find(ZZ &dst, raw_data x, Paillier::Encryptor &enc);
    void send(Channel &chl);
    int64_t get_pad();
    void deserialize();
    void verify(raw_data x, Paillier::Encryptor &enc, Paillier::Decryptor &dec);
};

#endif