#include "KeyStore.h"
#include "EncSumFilter.h"
raw_data *data_sender;
void data_loader_service(string path)
{
    ifstream fp(path);
    for (int i = 0; i < NX; i++)
    {
        raw_data t;
        fp >> t;
        data_sender[i] = t;
    }
}

void psi_sender(Paillier::Decryptor &dec, Channel &chl)
{
    int n_batch = NY % BATCH_SIZE == 0 ? NY / BATCH_SIZE : NY / BATCH_SIZE + 1;
    for (int i = 0; i < n_batch; i++)
    {
        int left_batch = i * BATCH_SIZE;
        int right_batch = min((i + 1) * BATCH_SIZE, NY);
        int len_batch = right_batch - left_batch;
        // cout << "left_batch: " << left_batch << " right_batch: " << right_batch << " len: " << len_batch << endl;
        int n_package = len_batch % PACKAGE_SIZE == 0 ? len_batch / PACKAGE_SIZE : len_batch / PACKAGE_SIZE + 1;
        // cout << "n_package: " << n_package << endl;
        vector<HEnc::CTxt> cipher_list(n_package);

        for (int j = 0; j < n_package; j++)
        {
            int left_package = j * PACKAGE_SIZE;
            int right_package = min((j + 1) * PACKAGE_SIZE, len_batch);
            int len_package = right_package - left_package;
            // cout << "left_package: " << left_package << " right_package: " << right_package << " len: " << len_package << endl;
            vector<unsigned char> cipher_char_list;
            chl.recv(cipher_char_list);
            // cout << "rev cipher char list" << endl;
            ZZ cipher_res;
            NTL::ZZFromBytes(cipher_res, &cipher_char_list[0], cipher_char_list.size());
            HEnc::PTxt pt;
            HEnc::CTxt ct;
            ct.set_ct(cipher_res);
            dec.decrypt(ct, pt);
            vector<ZZ> res_unpacking;
            // res_unpacking.emplace_back(pt.get_pt());
            ZZ plain_res = pt.get_pt();
            unpacking(res_unpacking, plain_res, len_package);
            vector<raw_data> res;
            for (auto &p : res_unpacking)
            {
                res.emplace_back(NTL::to_ulong(p));
            }
            chl.send(res);
        }
    }
}

int user_servive(string endpoint)
{

    // network
    IOService ios(4);
    ios.showErrorMessages(true);
    string ip = "localhost";
    int port = 1212;
    string serversIpAddress(endpoint);
    std::string sessionHint = "party0_party1";
    Session server(ios, serversIpAddress, SessionMode::Server, sessionHint);
    Channel chl1 = server.addChannel();
    cout << "finish initial network" << endl;

    // Paillier
    Paillier::SecretKey sk;
    Paillier::PublicKey pk;
    ZZ tmp_p, tmp_q;
// #if LOAD
    cout << "Loading..." << endl;
    ifstream is("index/paillier");
    boost::archive::binary_iarchive ia(is);
    KeyStore key_store;
    ia >> key_store;
    key_store.load(tmp_p, tmp_q);
    Paillier::key_load(sk, pk, tmp_p, tmp_q);

    Paillier::Encryptor enc(pk);
    Paillier::Decryptor dec(sk);
    init_packing();
    // cout << "pk: " << pk.get_N() << endl;

    ZZ pk_zz = pk.get_N();
    long lbits = NTL::NumBits(pk_zz);
    long lbytes = (lbits + 7) / 8;
    vector<unsigned char> pk_zz_list = vector<unsigned char>(lbytes);
    NTL::BytesFromZZ(&pk_zz_list[0], pk_zz, lbytes);
    chl1.send(pk_zz_list);

    // hash function
    int m = ALPHA * (NX / N_BLOCK) + 64;
    HashFunctions hash_functions(1, m);
    chl1.send(hash_functions.get_seed());
    // cout << "&&&" << hash_functions.get_seed()[0] << endl;
    cout << "finish construct and send hash function" << endl;

    vector<int> block_id_list;
    chl1.recv(block_id_list);
    cout << "block cnt: " << block_id_list.size() << endl;


    // EncSumFilter
    auto start = chrono::high_resolution_clock::now();
    vector<EncSumFilter> enc_sum_filter_list;
    for (auto idx : block_id_list)
    {
        string path = "index/sum_filter_" + to_string(idx);
        ifstream is(path);
        boost::archive::binary_iarchive ia(is);
        enc_sum_filter_list.emplace_back(EncSumFilter());
        ia >> enc_sum_filter_list.back();
    }

    auto finish = chrono::high_resolution_clock::now();
    cout << "finish construct EncSumFilter using time: " << chrono::duration_cast<chrono::milliseconds>(finish - start).count() << " ms" << endl;

    cout << "construct EncSumFilter successfully" << endl;

    chl1.send(2);
    for (auto &p : enc_sum_filter_list)
    {
        p.send(chl1);
    }

    // // psi
    psi_sender(dec, chl1);

    std::cout << "Total Comm = " << (chl1.getTotalDataRecv() + chl1.getTotalDataSent()) / std::pow(2.0, 20) << " MB\n";

    return 0;
}

void build_ESF(int start, int end, int m, Paillier::Encryptor &enc, vector<vector<raw_data> *> &data_block)
{
    for (int idx = start; idx <= end; idx++)
    {
        // cout << "start: " << start << ", end: " << end << endl;
        cout << "construct enc filter " << idx << endl;
        EncSumFilter tmp(m, data_block[idx], enc);
        string path = "index/sum_filter_" + to_string(idx);
        ofstream os(path);
        boost::archive::binary_oarchive oa(os);
        oa << tmp;
    }
}

int build_index(string path, int thread_num)
{
    data_sender = new raw_data[NX];
    data_loader_service(path);
    cout << "finish load data!" << endl;
    auto start_time = chrono::high_resolution_clock::now();
    // Paillier
    Paillier::SecretKey sk;
    Paillier::PublicKey pk;
    ZZ tmp_p, tmp_q;
    ofstream os("index/paillier");
    boost::archive::binary_oarchive oa(os);
    Paillier::key_gen(sk, pk, BIT_LEN / 2, tmp_p, tmp_q);
    KeyStore key_store(tmp_p, tmp_q);
    oa << key_store;
    Paillier::Encryptor enc(pk);

    vector<vector<raw_data> *> data_block = vector<vector<raw_data> *>(N_BLOCK);
    int m = ALPHA * (NX / N_BLOCK) + 64;
    HashFunctions hash_functions(1, m);
    for (int i = 0; i < NX; i++)
    {
        int idx = hash_functions.get_block_id(data_sender[i], N_BLOCK);
        if (data_block[idx] == nullptr)
        {
            data_block[idx] = new vector<raw_data>();
        }
        data_block[idx]->emplace_back(data_sender[i]);
        // cout << "element sum: " << accumulate(sta.begin(), sta.end(), 0) << endl;
    }
    delete[] data_sender;
    boost::asio::thread_pool pool(thread_num);
    int start = 0;
    for (int i = 0; i < thread_num; i++)
    {
        int share_count = i < N_BLOCK % thread_num ? N_BLOCK / thread_num + 1 : N_BLOCK / thread_num;
        auto task = boost::bind(build_ESF, start, start + share_count - 1, m, ref(enc), ref(data_block));
        boost::asio::post(pool, task);
        start += share_count;
    }
    pool.join();
    auto finish_time = chrono::high_resolution_clock::now();
    cout << "finish building index using time: " << chrono::duration_cast<chrono::milliseconds>(finish_time - start_time).count() << " ms" << endl;
    return 0;
}