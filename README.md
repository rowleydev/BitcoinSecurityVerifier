## Bitcoin Security Verifier

This program demonstrates the algorithms and elliptical curve cryptography behind a brute force attack on bitcoin private keys using the OpenSSL library.

It is not meant as a practical attack and favours speed over style.

## Compilation

Compile as: `g++ -o btc-brute btc-brute.cpp -lcrypto -lpthread -std=c++11`

## Running 

Run as:

`./btc-brute pathToListOfTargetAddresses threadCount startingPrivateKey`

EG:

`./btc-brute targets 2 10000000000000000000`

Both compressed and uncompressed addresses are computed. 

Valid private keys are 1 to: 115792089237316195423570985008687907852837564279074904382605163141518161494336

As an example, create a file called targets containing the following addresses and start the initial trial key at: 10000000000000000000

`1EDZLWcW4biU4qRYPUTw2uwQbMiAkwDutq`

`13W2kfyAD84VJDm7bNjk7Tpfq9HasH9Pyv`
