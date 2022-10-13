#include "util.h"

#ifndef KEY_STORE
#define KEY_STORE

class KeyStore
{
private:
    friend class boost::serialization::access;

    template <class Archive>
    void serialize(Archive &ar, const unsigned int version)
    {
        ar & p_char_list;
        ar & q_char_list;
        ar & p_n_bytes;
        ar & q_n_bytes;
    }

public:
    vector<unsigned char> p_char_list;
    vector<unsigned char> q_char_list;
    int p_n_bytes;
    int q_n_bytes;
    KeyStore();
    KeyStore(ZZ &p, ZZ &q);
    void load(ZZ &p, ZZ &q);
};

#endif