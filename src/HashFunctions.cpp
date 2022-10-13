#include "HashFunctions.h"

HashFunctions::HashFunctions(int h, int m)
{
    this->m = m;
    // cout << "generage random seed" << endl;
    srand((unsigned)time(NULL));
    this->hash_seed = vector<int>(h);
    // cout << "generage hash seed" << endl;
    this->reset_hash_seed();
}

void HashFunctions::reset_hash_seed()
{
    int h = this->hash_seed.size();
    unordered_set<int> seed_set;
    // srand((unsigned)time(NULL));
    for (int i = 0; i < h; i++)
    {
        int random_seed = rand();
        while (seed_set.count(random_seed) != 0)
        {
            random_seed = rand();
        }
        seed_set.insert(random_seed);
        this->hash_seed[i] = random_seed;
    }
}

int HashFunctions::get_hash_value(int id, raw_data hash_key)
{
    uint32_t hash_value;
    uint32_t key = hash_key | (1L << 32 - 1);
    MurmurHash3_x86_32((void *)&key, sizeof(uint32_t), this->hash_seed[id], (void *)&hash_value);
    uint32_t domain = id == H - 1 ? m - (H - 1) * (m / H) : m / H;
    // cout << "seed: " << this->hash_seed[id] << ", id: " << id << ", key: " << hash_key << ", value: " << (int)(hash_value % domain + id * (m / H)) <<  endl;
    return (int)(hash_value % domain + id * (m / H));
}

uint32_t HashFunctions::get_block_id(raw_data hash_key, int n_block)
{
    uint32_t hash_value;
    uint32_t key = hash_key | (1L << 32 - 1);
    MurmurHash3_x86_32((void *)&key, sizeof(uint32_t), BLOCK_SEED, (void *)&hash_value);
    // cout << "&&& " << hash_value << endl;
    return (uint32_t)(hash_value % n_block);
}

HashFunctions::HashFunctions(vector<int> seeds, int m)
{
    this->hash_seed = seeds;
    this->m = m;
}

HashFunctions::HashFunctions()
{
}

vector<int> HashFunctions::get_seed()
{
    return this->hash_seed;
}
