#include "MurmurHash3.h"
#include "util.h"

#ifndef HASH_FUNCTION
#define HASH_FUNCTION

class HashFunctions
{
private:
    friend class boost::serialization::access;

    template <class Archive>
    void serialize(Archive &ar, const unsigned int version)
    {
        ar & hash_seed;
        ar & m;
    }

public:
    vector<int> hash_seed;
    int m;
    HashFunctions();
    HashFunctions(int h, int m);
    HashFunctions(vector<int> seeds, int m);
    int get_hash_value(int id, raw_data hash_key);
    uint32_t get_block_id(raw_data hash_key, int n_block);
    void reset_hash_seed(int m);
    vector<int> get_seed();
};

#endif