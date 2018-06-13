/* 
   This program is designed to demonstrate the algorithms and elliptical curve 
   cryptography behind a brute force attack on bitcoin private keys. It is not 
   meant as a practical attack and favours speed over style.

   Compile as: g++ -o btc-brute btc-brute.cpp -lcrypto -std=c++11
   Run as:     btc-brute pathToListOfTargetAddresses initialDecimalTrialKey
   EG:	       btc-brute listOfAddresses 10000000000000000000

   Both compressed and uncompressed addresses are computed. Public keys are 
   further hashed for compatibility with std::unordered_set

   Valid private keys are 1 to:
   115792089237316195423570985008687907852837564279074904382605163141518161494336

   As an example create a text file containing the addresses: 

	1EDZLWcW4biU4qRYPUTw2uwQbMiAkwDutq
	13W2kfyAD84VJDm7bNjk7Tpfq9HasH9Pyv

   and start the initial trial key at: 10000000000000000000
*/

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/ripemd.h>
#include <vector>
#include <string.h>
#include <unordered_set>
#include <fstream>
#include <iostream>
#include <time.h>  

#include "conversions.h"

typedef unsigned long long longlong;

void sha256(unsigned char* input, unsigned char* hash, int length);
void ripe160(unsigned char* buffer);
void charToBinary(unsigned char* input, unsigned char* output);
void loadTargets(char * fileName, std::unordered_set<longlong>& targets);
void printBigNum(BIGNUM* num);
longlong fastHash(unsigned char* input);

RIPEMD160_CTX ripeContext;
SHA256_CTX sha256Context;

int main(int argc, char* args[])
{
	if (argc != 3)
	{ 
		printf("Invalid arguments"); 
		exit(0); 
	}

	// Load target addresses
	std::unordered_set<longlong> targets;
	loadTargets(args[1], targets);

	// Private key and trial increment
	BIGNUM* privateKey = BN_new();
	BIGNUM* one = BN_new();
	BN_dec2bn(&one, "1");

	// Load the ascii private key
	BN_dec2bn(&privateKey, args[2]);

	// Public keys
	BIGNUM* publicKeyBN = BN_new();
	BIGNUM* publicKeyUCBN = BN_new();

	// OpenSSL library initialisation
	BN_CTX* bignumContext =	BN_CTX_new();
	EC_KEY* ecKey = EC_KEY_new_by_curve_name(OBJ_txt2nid("secp256k1"));
	const EC_GROUP* ecGroup = EC_KEY_get0_group(ecKey);
	EC_POINT* publicKey = EC_POINT_new(ecGroup);

	// Buffers
	unsigned char* publicKeyBin = (unsigned char*)malloc(33);
	unsigned char* publicKeyUCBin = (unsigned char*)malloc(67);
	unsigned char* hashBuffer = (unsigned char*)malloc(64);
	unsigned char* hashBufferUC = (unsigned char*)malloc(128);

	printf("\n\nStarting...\n");

	for (unsigned int i = 0; ;i++)
	{
		// Compute public key
		EC_POINT_mul(ecGroup, publicKey, privateKey, NULL, NULL, bignumContext);

		// Compute compressed address
		EC_POINT_point2bn(ecGroup, publicKey, POINT_CONVERSION_COMPRESSED, publicKeyBN, bignumContext);
		BN_bn2bin(publicKeyBN, publicKeyBin);
		sha256(publicKeyBin, hashBuffer, 33);
		ripe160(hashBuffer);
		longlong hashValue = fastHash(hashBuffer);

		// Search targets
		if (targets.find(hashValue) != targets.end())
		{
			printf("\n\nFound compressed private key: ");
			printBigNum(privateKey);
			printf("\n");
			fflush(stdout);
		}

		// Compute uncompressed address
		EC_POINT_point2bn(ecGroup, publicKey, POINT_CONVERSION_UNCOMPRESSED, publicKeyUCBN, bignumContext);
		BN_bn2bin(publicKeyUCBN, publicKeyUCBin);
		sha256(publicKeyUCBin, hashBufferUC, 65);
		ripe160(hashBufferUC);
		longlong hashValueUC = fastHash(hashBufferUC);
	
		// Search targets
		if (targets.find(hashValueUC) != targets.end())
		{
			printf("\n\nFound uncompressed private key: ");
			printBigNum(privateKey);
			printf("\n");
			fflush(stdout);
		}
	
		// Output progress
		if (i % 10000 == 0)
		{
			printf("\nCount: %9i Key: ", i);
			printBigNum(privateKey);
			fflush(stdout);
		}

		// Select new private key
		BN_add(privateKey, privateKey, one);
	}
}

void printBigNum(BIGNUM* num)
{
	char* buffer = BN_bn2dec(num);
	printf("%s", buffer);
	delete[] buffer;
}

void loadTargets(char* fileName, std::unordered_set<longlong>& targets)
{
	printf("\nLoading targets from: %s", fileName);

	int i = 0;
	std::ifstream infile(fileName);

	// Buffers for address decoding stages
	char fileLineBuffer[64];
	unsigned char binaryBuffer[20];
	std::vector<unsigned char>* ripeAddressBuffer = new std::vector<unsigned char>();
	unsigned char outputBuffer[48];
	outputBuffer[20] = 0;

	while (infile >> fileLineBuffer)
	{
		i++;

		// Decode base58 address
		if (!decodeBase58(fileLineBuffer, *ripeAddressBuffer))
		{
			printf("\nCould not decode address: %s", fileLineBuffer);
		}

		// Convert checksummed ripe hash to just the ripe hash
		stripCheckedRipe(ripeAddressBuffer, outputBuffer);

		// Convert ripe ascii string to binary
		charToBinary(outputBuffer, binaryBuffer);

		// Hash the ripe hash with the custom hash
		longlong hashvalue = fastHash(binaryBuffer);
		targets.insert(hashvalue);
	}

	printf("\nTargets loaded      : %i", i);
	fflush(stdout);

	if (i == 0)
	{
		printf("\nNo target addresses found");
		exit(0);
	}
}

// A fast custom hash that produces an output compatible with std::unordered_set
// by treating the binary data directly as a long long
inline longlong fastHash(unsigned char* input)
{
	return *(longlong*)(input);
}

inline void ripe160(unsigned char* buffer)
{
	RIPEMD160_Init(&ripeContext);
	RIPEMD160_Update(&ripeContext, buffer, 32);
	RIPEMD160_Final(buffer, &ripeContext);
}

inline void sha256(unsigned char* input, unsigned char* hash, int length)
{
	SHA256_Init(&sha256Context);
	SHA256_Update(&sha256Context, input, length);
	SHA256_Final(hash, &sha256Context);
}