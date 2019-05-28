#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/ripemd.h>

#include "task-parameters.h"
#include "conversions.h"

void* task(void* inputParams)
{
	// Extract task parameters
	TaskParameters* taskParameters = (TaskParameters*)inputParams;
	void (*reportProgress)(BIGNUM*, int) = taskParameters->reportProgress;
	void (*checkTargets)(longlong, BIGNUM*, int, const char*) = taskParameters->checkTargets;
	int id = taskParameters->id;
	BIGNUM* privateKey = taskParameters->start;
	BIGNUM* increment = taskParameters->increment;

	// Public keys
	BIGNUM* publicKeyBN = BN_new();
	BIGNUM* publicKeyUCBN = BN_new();

	// OpenSSL library initialisation
	BN_CTX* bignumContext =	BN_CTX_new();
	EC_KEY* ecKey = EC_KEY_new_by_curve_name(OBJ_txt2nid("secp256k1"));
	const EC_GROUP* ecGroup = EC_KEY_get0_group(ecKey);
	EC_POINT* publicKey = EC_POINT_new(ecGroup);

	// Hash contexts
	RIPEMD160_CTX ripeContext;
	SHA256_CTX sha256Context;

	// Buffers
	unsigned char* publicKeyBin = (unsigned char*)malloc(33);
	unsigned char* publicKeyUCBin = (unsigned char*)malloc(67);
	unsigned char* hashBuffer = (unsigned char*)malloc(32);

	for (unsigned int i = 0; ;i++)
	{
		// Compute public key
		EC_POINT_mul(ecGroup, publicKey, privateKey, NULL, NULL, bignumContext);

		// Compute compressed address
		EC_POINT_point2bn(ecGroup, publicKey, POINT_CONVERSION_COMPRESSED, publicKeyBN, bignumContext);
		BN_bn2bin(publicKeyBN, publicKeyBin);

		// SHA256 public key into hashBuffer
		SHA256_Init(&sha256Context);
		SHA256_Update(&sha256Context, publicKeyBin, 33);
		SHA256_Final(hashBuffer, &sha256Context);

		// RIPE160 the hashbuffer
		RIPEMD160_Init(&ripeContext);
		RIPEMD160_Update(&ripeContext, hashBuffer, 32);
		RIPEMD160_Final(hashBuffer, &ripeContext);

		// Compute compatible hash value
		longlong hashValue = fastHash(hashBuffer);

		// Search targets
		checkTargets(hashValue, privateKey, id, "\nThread %i Found compressed private key: ");

		// Compute uncompressed address
		EC_POINT_point2bn(ecGroup, publicKey, POINT_CONVERSION_UNCOMPRESSED, publicKeyUCBN, bignumContext);
		BN_bn2bin(publicKeyUCBN, publicKeyUCBin);

		// SHA256 public key into hashBuffer
		SHA256_Init(&sha256Context);
		SHA256_Update(&sha256Context, publicKeyUCBin, 65);
		SHA256_Final(hashBuffer, &sha256Context);

		// RIPE160 the hashbuffer
		RIPEMD160_Init(&ripeContext);
		RIPEMD160_Update(&ripeContext, hashBuffer, 32);
		RIPEMD160_Final(hashBuffer, &ripeContext);

		// Compute compatible hash value
		longlong hashValueUC = fastHash(hashBuffer);

		// Search targets
		checkTargets(hashValueUC, privateKey, id, "\nThread %i Found uncompressed private key: ");
	
		// Output progress
		if (i % 10000 == 0)
		{
			reportProgress(privateKey, id);
		}

		// Select next private key
		BN_add(privateKey, privateKey, increment);
	}
}
