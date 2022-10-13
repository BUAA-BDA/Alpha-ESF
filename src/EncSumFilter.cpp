#include "EncSumFilter.h"

EncSumFilter::EncSumFilter() {}

EncSumFilter::EncSumFilter(int m, vector<raw_data> *data, Paillier::Encryptor &enc) : hash_function(H, m)
{
    this->m = m;
    this->byte_length = vector<int>(m);
    vector<raw_data> order_data;
    // vector<unordered_set<raw_data>> bloom_set(m);
    // cout << "data size: " << data->size() << " m: " << m << endl;
    mt19937 rng(random_device{}());
    unordered_set<raw_data> data_dup;
    for (auto &p : *data)
    {
        data_dup.emplace(p);
    }
    // cout << "data dup size: " << data_dup.size() << " m: " << m << endl;
    int cnt = 0;
    do
    {
        cnt++;
        // assert(cnt < 1000);
        order_data.clear();
        hash_function.reset_hash_seed();
        vector<unordered_set<raw_data>> bloom_set(m);
        for (auto p : data_dup)
        {
            for (int i = 0; i < H; i++)
            {
                // cout << "p" << p << ", id" << hash_function.get_hash_value(i, p) << endl;
                bloom_set[hash_function.get_hash_value(i, p)].emplace(p);
            }
        }
        queue<int> qu;
        for (int i = 0; i < m; i++)
        {
            if (bloom_set[i].size() == 1)
            {
                qu.emplace(i);
            }
        }
        // cout << "qu size: " << qu.size() << endl;
        while (!qu.empty())
        {
            int tmp_idx = qu.front();
            qu.pop();
            if (bloom_set[tmp_idx].size() == 0)
            {
                continue;
            }
            raw_data tmp_data = *bloom_set[tmp_idx].begin();
            bloom_set[tmp_idx].erase(tmp_data);
            order_data.emplace_back(tmp_data);
            for (int t = 0; t < H; t++)
            {
                int idx = hash_function.get_hash_value(t, tmp_data);
                if (bloom_set[idx].count(tmp_data) != 0)
                {
                    bloom_set[idx].erase(tmp_data);
                    if (bloom_set[idx].size() == 1)
                    {
                        qu.emplace(idx);
                    }
                }
            }
        }
        // cout << "order_data size: " << order_data.size() << endl;
    } while (order_data.size() != data_dup.size());
    // cout << "order data size: " << order_data.size() << " try cnt: " << cnt << endl;
    // assert(order_data.size() == data.size());
    vector<int64_t> tmp_bloom(m);
    unordered_set<int> occupied;
    for (int u = order_data.size() - 1; u >= 0; u--)
    {
        raw_data p = order_data[u];
        vector<int> free_pos;
        unordered_set<int> eli_dup;
        int64_t existed = 0L;
        for (int i = 0; i < H; i++)
        {
            int idx = hash_function.get_hash_value(i, p);
            if (eli_dup.count(idx) != 0)
            {
                continue;
            }
            eli_dup.insert(idx);
            if (occupied.count(idx) != 0)
            {
                existed = existed + tmp_bloom[idx];
            }
            else
            {
                free_pos.emplace_back(idx);
            }
        }
        if (free_pos.empty())
        {
            cout << "#: " << p << ": fails" << endl;
        }
        int64_t randoms = 0L;
        for (int i = 0; i < free_pos.size() - 1; i++)
        {
            tmp_bloom[free_pos[i]] = LOWER_BOUND + rng() % (UPPER_BOUND - LOWER_BOUND);
            randoms = randoms + tmp_bloom[free_pos[i]];
            occupied.insert(free_pos[i]);
        }
        int last_id = free_pos[free_pos.size() - 1];
        occupied.insert(last_id);

        randoms += existed;
        tmp_bloom[last_id] = p - randoms;
    }
    for (int i = 0; i < m; i++)
    {
        if (occupied.count(i) == 0)
        {
            tmp_bloom[i] = LOWER_BOUND + rng() % (UPPER_BOUND - LOWER_BOUND);
        }
    }
    int64_t min_ele = *min_element(tmp_bloom.begin(), tmp_bloom.end());
    this->pad = min_ele < 0 ? -1 * min_ele : 0;
    for (int i = 0; i < m; i++)
    {
        tmp_bloom[i] += this->pad;
        HEnc::PTxt pt;
        HEnc::CTxt ct;
        pt.set_pt(ZZ(tmp_bloom[i]));
        enc.encrypt(pt, ct);
        long lbits = NTL::NumBits(ct.get_ct());
        long lbytes = (lbits + 7) / 8;
        vector<unsigned char> tmp = vector<unsigned char>(lbytes);
        this->byte_length[i] = i == 0 ? lbytes : this->byte_length[i - 1] + lbytes;
        NTL::BytesFromZZ(&tmp[0], ct.get_ct(), lbytes);
        copy(tmp.begin(), tmp.end(), back_inserter(this->bloom));
    }
}

void EncSumFilter::deserialize()
{
    for (int i = 0; i < m; i++)
    {
        int left = i == 0 ? 0 : this->byte_length[i - 1];
        NTL::ZZFromBytes(this->cipher_bloom[i], &(this->bloom[left]), this->byte_length[i] - left);
    }
}

void EncSumFilter::find(ZZ &dst, raw_data x, Paillier::Encryptor &enc)
{
    dst = 0;
    HEnc::CTxt ct;
    for (int i = 0; i < H; i++)
    {
        int idx = hash_function.get_hash_value(i, x);
        if (this->cipher_bloom.count(idx) == 0)
        {
            int left = idx == 0 ? 0 : this->byte_length[idx - 1];
            NTL::ZZFromBytes(this->cipher_bloom[idx], &(this->bloom[left]), this->byte_length[idx] - left);
        }
        if (i == 0)
        {
            ct.set_ct(this->cipher_bloom[idx]);
        }
        else
        {
            HEnc::CTxt ct1;
            ct1.set_ct(this->cipher_bloom[idx]);
            enc.he_add(ct, ct1, ct);
        }
    }
    dst = ct.get_ct();
}

void EncSumFilter::send(Channel &chl)
{
    chl.send(this->hash_function.get_seed());
    chl.send(this->pad);
    chl.send(this->byte_length);
    chl.send(this->bloom);
    // cout << "pad: " << this->pad << endl;
}

EncSumFilter::EncSumFilter(Channel &chl, int m)
{
    this->m = m;
    vector<int> seeds;
    chl.recv(seeds);
    chl.recv(this->pad);
    chl.recv(this->byte_length);
    chl.recv(this->bloom);
    this->hash_function = HashFunctions(seeds, m);
    // cout << "pad: " << this->pad << endl;

    assert(this->byte_length.size() == m);
}

int64_t EncSumFilter::get_pad()
{
    return this->pad;
}

void EncSumFilter::verify(raw_data x, Paillier::Encryptor &enc, Paillier::Decryptor &dec)
{
    cout << "verify: " << x << endl;
    ZZ t;
    this->find(t, x, enc);
    HEnc::CTxt ct;
    HEnc::PTxt pt;
    ct.set_ct(t);
    dec.decrypt(ct, pt);
    cout << "verify result: " << pt.get_pt() << endl;
}