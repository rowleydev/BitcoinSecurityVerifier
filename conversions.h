int charToInt(unsigned char input)
{
	if (input >= '0' && input <= '9')
	{
		return input - '0';
	}
	if (input >= 'A' && input <= 'F')
	{
		return input - 'A' + 10;
	}
	if (input >= 'a' && input <= 'f')
	{
		return input - 'a' + 10;
	}
}

void charToBinary(unsigned char* input, unsigned char* output)
{
	while (*input && (input[1] != '\n'))
	{
		*(output++) = charToInt(*input) * 16 + charToInt(input[1]);
		input += 2;
	}
}

void stripCheckedRipe(std::vector<unsigned char>* input, unsigned char* output)
{
	int j = 0;
	for (std::vector<unsigned char>::const_iterator i = input->begin() + 1; i != input->end() - 4; ++i)
	{
		sprintf((char*)output + j, "%02x", *i);
		j += 2;
	}
}

// This function courtesy of https://github.com/bitcoin/bitcoin
static const char* pszBase58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
bool decodeBase58(const char *psz, std::vector<unsigned char>& vch)
{
	// Skip leading spaces
	while (*psz && isspace(*psz))
	{
		psz++;
	}

	// Skip and count leading '1's
	int zeroes = 0;
	while (*psz == '1')
	{
		zeroes++;
		psz++;
	}

	// Allocate enough space in big-endian base256 representation
	std::vector<unsigned char> b256(strlen(psz) * 733 / 1000 + 1);

	// Process the characters
	while (*psz)
	{
		// Decode base58 character
		const char *ch = strchr(pszBase58, *psz);
		if (ch == NULL)
		{
			return false;
		}

		// Apply "b256 = b256 * 58 + ch"
		int carry = ch - pszBase58;
		for (std::vector<unsigned char>::reverse_iterator it = b256.rbegin(); it != b256.rend(); it++)
		{
			carry += 58 * (*it);
			*it = carry % 256;
			carry /= 256;
		}

		psz++;
	}

	// Skip trailing spaces
	while (isspace(*psz))
	{
		psz++;
	}

	if (*psz != 0)
	{
		return false;
	}

	// Skip leading zeroes in base 256
	std::vector<unsigned char>::iterator it = b256.begin();
	while (it != b256.end() && *it == 0)
	{	
		it++;
	}

	// Copy result into output vector
	vch.reserve(zeroes + (b256.end() - it));
	vch.assign(zeroes, 0x00);

	while (it != b256.end())
	{
		vch.push_back(*(it++));
	}

	return true;
}