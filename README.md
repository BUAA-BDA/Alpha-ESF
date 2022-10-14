# Alpha-ESF

## Feature

This is an implementation of a practical unbalanced set intersection method $\alpha$-ESF, where the server-side dataset can amount to billion scale. In the processing of PSI, the client can learn the PSI result, while the server should not learn any additional information. We also provide an example on synthetic dataset below.

## Environment

* Ubuntu 18.04
* g++ 9.4.0
* cmake 3.24.0

## Required Libraries

* [NTL 11.5.1](https://libntl.org/)
* [GMP 6.2.1](https://gmplib.org/)
* [Boost 1.77.0](https://www.boost.org/users/history/version_1_77_0.html)
* [CryptoTools](https://github.com/ladnir/cryptoTools)
* [Henc](thirdparty/henc/README.en.md)

## Compilation

```bash
mkdir build && cd build
cmake ..
make
cd ..
```

## Test

* Bucket-ESF index construction

  ```bash
  mkdir index
  ./main --build --path data/psi_200.txt --Ns 200 --B 10 
  ```

* Start up server

  ```bash
  ./main --r 0 --endpoint localhost:1212 --Ns 200 --Nc 100 --Alpha 10 --B 10
  ```

* Start up client

  ```bash
  ./main --r 1 --path data/psi_100.txt --endpoint localhost:1212 --Ns 200 --Nc 100 --Alpha 10 --B 10
  ```

* For more information, you can use `--help` flag

  ```bash
  ./main --help
  All options for Alpha-ESF:
    --help                Produce help message
    --build               build ESF index
    --path arg            file path
    --endpoint arg        ip address and port
    --r arg               party ID
    --Ns arg              data size of server
    --Nc arg              data size of client
    --Alpha arg           alpha indistinguishablity
    --B arg               the number of buckets
  ```
