/*
   This program is designed to demonstrate the algorithms and elliptical curve
   cryptography behind a brute force attack on bitcoin private keys. It is not
   meant as a practical attack and favours speed over style.

   Compile as: g++ -o btc-brute btc-brute.cpp -lcrypto -lpthread -std=c++11
   Run as:     btc-brute pathToListOfTargetAddresses threadCount startingPrivateKey
   EG:	       btc-brute targets 2 10000000000000000000

   Both compressed and uncompressed addresses are computed. Public keys are
   further hashed for compatibility with std::unordered_set

   Valid private keys are 1 to:
   115792089237316195423570985008687907852837564279074904382605163141518161494336

   As an example create a file called targets containing the addresses:

	1EDZLWcW4biU4qRYPUTw2uwQbMiAkwDutq
	13W2kfyAD84VJDm7bNjk7Tpfq9HasH9Pyv

   and start the initial trial key at: 10000000000000000000
*/

#include <openssl/bio.h>
#include <pthread.h>
#include <unordered_set>

#include "conversions.h"
#include "load-targets.h"
#include "btc-compute.h"
#include "task-parameters.h"

void reportProgress(BIGNUM* value, int id);
void checkTargets(longlong value, BIGNUM* privateKey, int id, const char* message);
void output(BIGNUM* bignum, int id, const char* format);
void printBigNum(BIGNUM* num);

std::unordered_set<longlong> targets;
pthread_mutex_t outputMutex = PTHREAD_MUTEX_INITIALIZER;

int main(int argc, char* args[])
{
	if (argc != 4)
	{
		printf("Usage: pathToListOfTargetAddresses threadCount startingPrivateKey\n");
		exit(0);
	}

	int threadCount = atoi(args[2]);

	BIGNUM* one = BN_new();
	BN_dec2bn(&one, "1");

	// Load target addresses
	loadTargets(args[1], targets);

	// Starting private key
	BIGNUM* startingPrivateKey = BN_new();
	BN_dec2bn(&startingPrivateKey, args[3]);

	// Increment == number of threads
	BIGNUM* increment = BN_new();
	BN_dec2bn(&increment, args[2]);

	// Create thread array
	pthread_t* threads = new pthread_t[threadCount];

	for (int i = 0; i < threadCount; i++)
	{
		BIGNUM* privateKey = BN_dup(startingPrivateKey);

		TaskParameters* taskParameters = new TaskParameters{ privateKey, increment, i, checkTargets, reportProgress };

		output(privateKey, i, "\nCreating thread: %i, starting value: ");

		pthread_create(&(threads[i]), NULL, task, taskParameters);

		// Start each thread with a different private key
		BN_add(startingPrivateKey, startingPrivateKey, one);
	}

	getchar();
	return 0;
}

void checkTargets(longlong value, BIGNUM* privateKey, int id, const char* message)
{
	if (targets.find(value) != targets.end())
	{
		output(privateKey, id, message);
	}
}

void reportProgress(BIGNUM* value, int id)
{
	output(value, id, "\nProgress thread %i: ");
}

void output(BIGNUM* bignum, int id, const char* format)
{
	// Spin wait for output
	while (pthread_mutex_trylock(&outputMutex) == EBUSY)
	{
	}

	printf(format, id);
	printBigNum(bignum);
	fflush(stdout);

	pthread_mutex_unlock(&outputMutex);
}

void printBigNum(BIGNUM* num)
{
	char* buffer = BN_bn2dec(num);
	printf("%s", buffer);
	delete[] buffer;
}
