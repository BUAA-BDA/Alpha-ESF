#include "EncSumFilter.h"

raw_data *data_recv;
void data_loader_client(string path)
{
    ifstream fp(path);
    for (int i = 0; i < NY; i++)
    {
        raw_data t;
        fp >> t;
        data_recv[i] = t;
    }
}

void psi_recv(vector<raw_data> &res, Paillier::Encryptor &enc, vector<EncSumFilter> &filter_list, unordered_map<int, int> data2pos, HashFunctions &hash_functions, Channel &chl)
{
    mt19937 rng(random_device{}());
    int n_batch = NY % BATCH_SIZE == 0 ? NY / BATCH_SIZE : NY / BATCH_SIZE + 1;
    for (int i = 0; i < n_batch; i++)
    {
        int left_batch = i * BATCH_SIZE;
        int right_batch = min((i + 1) * BATCH_SIZE, NY);
        int len_batch = right_batch - left_batch;
        // cout << "left: " << left_batch << " right: " << right_batch << " len: " << len_batch << endl;
        int n_package = len_batch % PACKAGE_SIZE == 0 ? len_batch / PACKAGE_SIZE : len_batch / PACKAGE_SIZE + 1;
        vector<HEnc::CTxt> cipher_list(n_package);
        for (int j = 0; j < n_package; j++)
        {
            int left_package = j * PACKAGE_SIZE;
            int right_package = min((j + 1) * PACKAGE_SIZE, len_batch);
            int len_package = right_package - left_package;
            vector<raw_data> data_list(len_package);
            vector<ZZ> bloom_list(len_package);
            vector<int64_t> pad_list(len_package);
            vector<raw_data> rand_list(len_package);
            //  cout << "left_package: " << left_package << " right_package: " << right_package << " len: " << len_package << endl;
            for (int t = i * BATCH_SIZE + left_package; t < i * BATCH_SIZE + right_package; t++)
            {
                // cout << t - i * BATCH_SIZE << " : " << t << endl;
                rand_list[t - i * BATCH_SIZE - left_package] = LOWER_BOUND + rng() % (UPPER_BOUND - LOWER_BOUND);
                data_list[t - i * BATCH_SIZE - left_package] = data_recv[t] + rand_list[t - i * BATCH_SIZE - left_package];
                filter_list[data2pos[data_recv[t]]].find(bloom_list[t - i * BATCH_SIZE - left_package], data_recv[t], enc);
                pad_list[t - i * BATCH_SIZE - left_package] = filter_list[data2pos[data_recv[t]]].get_pad() * H;
            }
            ZZ data_pack, bloom_pack;
            packing(data_pack, data_list, pad_list);
            packing(bloom_pack, bloom_list, enc);
            HEnc::PTxt pt1, r;
            HEnc::CTxt ct1, ct2;
            pt1.set_pt(data_pack);
            ct2.set_ct(bloom_pack);
            enc.encrypt(pt1, ct1);
            enc.he_sub(ct1, ct2, cipher_list[j]);
            ZZ cipher = cipher_list[j].get_ct();
            long lbits = NTL::NumBits(cipher);
            long lbytes = (lbits + 7) / 8;
            vector<unsigned char> cipher_char_list = vector<unsigned char>(lbytes);
            NTL::BytesFromZZ(&cipher_char_list[0], cipher, lbytes);
            chl.send(cipher_char_list);
            vector<raw_data> res_list;
            chl.recv(res_list);
            assert(res_list.size() == len_package);
            for (int t = 0; t < res_list.size(); t++)
            {
                if (res_list[t] == rand_list[t])
                {
                    res.emplace_back(data_recv[t + i * BATCH_SIZE + left_package]);
                }
            }
        }
    }
}

template<typename ... Args>
std::string string_format(const std::string& format, Args ... args)
{
	size_t size = std::snprintf(nullptr, 0, format.c_str(), args ...) + 1; // Extra space for '\0'
	std::unique_ptr<char[]> buf(new char[size]);
	std::snprintf(buf.get(), size, format.c_str(), args ...);
	return std::string(buf.get(), buf.get() + size - 1); // We don't want the '\0' inside
}

int user_client(string endpoint, string path)
{

    data_recv = new raw_data[NY];
    data_loader_client(path);
    cout << "finish load data!" << endl;

    // network
    IOService ios(4);
    ios.showErrorMessages(true);
    string ip = "localhost";
    int port = 1212;
    string serversIpAddress(endpoint);
    std::string sessionHint = "party0_party1";
    Session client(ios, serversIpAddress, SessionMode::Client, sessionHint);
    Channel chl0 = client.addChannel();
    cout << "finish initial network" << endl;

    // Paillier
    vector<unsigned char> pk_char_list;
    chl0.recv(pk_char_list);
    ZZ pk_zz;
    NTL::ZZFromBytes(pk_zz, &pk_char_list[0], pk_char_list.size());
    Paillier::PublicKey pk(pk_zz);
    Paillier::Encryptor enc(pk);
    init_packing();
    // cout << "pk: " << pk.get_N_square() << endl;

    // hash function
    int m = ALPHA * (NX / N_BLOCK) + 64;
    vector<int> seeds;
    chl0.recv(seeds);
    HashFunctions hash_functions(seeds, m);
    cout << "finish receive and construct hash function" << endl;
    std::random_device rd;
    std::mt19937 mt(rd());

    // blocking
    std::set<int> block_id_set;
    int block_size = NX / N_BLOCK;
    std::uniform_int_distribution<int> distrib(0, N_BLOCK - 1);
    for (int i = 0; i < NY; i++)
    {
        int block_id = hash_functions.get_block_id(data_recv[i], N_BLOCK);
        if (block_id_set.count(block_id) == 0)
        {
            block_id_set.insert(block_id);
            for (int t = 0; t < K_IND / block_size; t++)
            {
                block_id_set.insert(distrib(mt));
            }
        }
    }
    vector<int> block_id_list;
    copy(block_id_set.begin(), block_id_set.end(), back_inserter(block_id_list));
    // iota(block_id_list.begin(), block_id_list.end(), 0);
    cout << "block cnt: " << block_id_list.size() << endl;
    chl0.send(block_id_list);

    unordered_map<int, int> id2pos;
    for (int i = 0; i < block_id_list.size(); i++)
    {
        id2pos[block_id_list[i]] = i;
    }

    unordered_map<int, int> data2pos;
    for (int i = 0; i < NY; i++)
    {
        // assert(id2pos[hash_functions.get_block_id(data_recv[i], N_BLOCK)] == 0);
        data2pos[data_recv[i]] = id2pos[hash_functions.get_block_id(data_recv[i], N_BLOCK)];
    }

    int tag;
    chl0.recv(tag);
    auto start = chrono::high_resolution_clock::now();
    // EncSumFilter
    vector<EncSumFilter> enc_sum_filter_list;
    for (int i = 0; i < block_id_list.size(); i++)
    {
        enc_sum_filter_list.emplace_back(chl0, m);
    }
    cout << "finish construct enc sum filter" << endl;
    // // auto start = chrono::high_resolution_clock::now();
    // // psi
    auto mid = chrono::high_resolution_clock::now();
    vector<raw_data> psi_result;
    psi_recv(psi_result, enc, enc_sum_filter_list, data2pos, hash_functions, chl0);
    auto finish = chrono::high_resolution_clock::now();
    
    cout << "============================= psi result =================================" << endl;
    for (auto p : psi_result)
    {
        cout << p << endl;
    }
    cout << "finish psi using time: " << chrono::duration_cast<chrono::milliseconds>(finish - start).count() << " ms" << endl;
    cout << "finish psi computation using time: " << chrono::duration_cast<chrono::milliseconds>(finish - mid).count() << " ms" << endl;
    cout << "psi count is " << psi_result.size() << endl;
    std::cout << "Total Comm = " << string_format("%5.2f", (chl0.getTotalDataRecv() + chl0.getTotalDataSent()) / std::pow(2.0, 20)) << " MB\n";

    delete[] data_recv;
    return 0;
}