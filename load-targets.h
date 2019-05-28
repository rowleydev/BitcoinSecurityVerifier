#include "conversions.h"
#include <fstream>

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

	printf("\nTargets loaded: %i", i);
	fflush(stdout);
	infile.close();

	if (i == 0)
	{
		printf("\nNo target addresses found");
		exit(0);
	}
}
