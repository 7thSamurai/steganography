#pragma once

#include <cstdint>
#include <cstdio>
#if defined(__linux__) || defined(__APPLE__)
#elif defined(_WIN32)
#include <windows.h>
#include <wincrypt.h>
#else
#error "Unsupported OS"
#endif


class Random
{

#if defined(__linux__) || defined(__APPLE__)
public:
	Random() {
		file = fopen("/dev/urandom", "rb");
	}
	~Random() {
		if (file)
			fclose(file);
	}

	void get(void* data, std::size_t size) {

		fread(data, size, 1, file);
	}

private:
	FILE* file;

#elif defined(_WIN32)
public:
	Random() {
		if (!CryptAcquireContext(
			&hCryptProv,               // handle to the CSP
			UserName,                  // container name 
			NULL,                      // use the default provider
			PROV_RSA_FULL,             // provider type
			0))                        // flag values
		{
			if (GetLastError() == NTE_BAD_KEYSET)
			{
				if (CryptAcquireContext(
					&hCryptProv,
					UserName,
					NULL,
					PROV_RSA_FULL,
					CRYPT_NEWKEYSET))
				{
					printf("A new key container has been created.\n");
				}
				else
				{
					printf("Could not create a new key container.\n");
					exit(1);
				}
			}
			else
			{
				printf("A cryptographic service handle could not be "
					"acquired.\n");
				exit(1);
			}			
		}
	}
~Random() {
	CryptReleaseContext(hCryptProv, 0);
}

void get(void* data, std::size_t size) {
	CryptGenRandom(hCryptProv, size, (BYTE*)data);
}

private:
	HCRYPTPROV hCryptProv = NULL;
	LPCSTR UserName = "MyKeyContainer";

#else
#error "Unsupported OS"
#endif
};
