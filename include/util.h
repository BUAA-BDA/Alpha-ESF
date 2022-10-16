#include "boost/any.hpp"
#include "boost/archive/binary_iarchive.hpp"
#include "boost/archive/binary_oarchive.hpp"
#include "boost/foreach.hpp"
#include "boost/serialization/serialization.hpp"
#include <algorithm>
#include <assert.h>
#include <boost/asio/post.hpp>
#include <boost/asio/thread_pool.hpp>
#include <boost/bind.hpp>
#include <boost/program_options.hpp>
#include <boost/serialization/export.hpp>
#include <boost/serialization/vector.hpp>
#include <chrono>
#include <cmath>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Network/Session.h>
#include <fstream>
#include <henc/paillier.h>
#include <iostream>
#include <iterator>
#include <memory>
#include <numeric>
#include <queue>
#include <random>
#include <set>
#include <sstream>
#include <stdlib.h>
#include <string>
#include <thread>
#include <time.h>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>
#include <vector>
using namespace std;
using namespace osuCrypto;
using namespace NTL;
namespace op = boost::program_options;
#ifndef UTIL
#define UTIL

#define H 3
#define B 200000
#define CUCKOO_HASH_TRY_LIMIT 500

// #define NX 1073741824
// #define NY 200

#define N 16384
#define BIT_LEN 512
#define PACKAGE_SIZE 10
#define BATCH_SIZE 60
#define ALPHA 1.23
#define PACKAGE_LEN 50
#define LOWER_BOUND 10000000000
#define UPPER_BOUND 99999999999
// #define N_BLOCK 100000
// #define K_IND 10000
#define LOAD 1
#define BLOCK_SEED 1458582678
extern long NX;
extern int NY;
// extern int PACKAGE_SIZE;
// extern int DES_OPT;
extern int K_IND;
extern int N_BLOCK;
typedef uint16_t hash_output;
typedef long raw_data;
void packing(ZZ &dst, vector<raw_data> &data, vector<int64_t> &pad_list);
void packing(ZZ &dst, vector<ZZ> &data, Paillier::Encryptor &enc);
void unpacking(vector<ZZ> &dst, ZZ &src, int len);
void ZZ2char(ZZ &src, unsigned char *dst);
void init_packing();
int user_servive(string endpoint);
int build_index(string path, int thread_num);
int user_client(string endpoint, string path);
#endif