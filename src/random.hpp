#pragma once

#include <cstdint>
#include <cstdio>
#if defined(__linux__) || defined(__APPLE__)
#elif defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#pragma comment( lib, "Bcrypt" )
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

	bool get(void* data, std::size_t size) {
		fread(data, size, 1, file);
		return true;
	}

private:
	FILE* file;

#elif defined(_WIN32)
public:
	Random() {

	}
	~Random() {
		
	}

	bool get(void* data, std::size_t size) {
		auto status = BCryptGenRandom(
			NULL,
			(BYTE*)data,
			size,
			BCRYPT_USE_SYSTEM_PREFERRED_RNG);

		if (!BCRYPT_SUCCESS(status))
		{
			std::cerr << "Unable to generate random number\n";
			return false;
		}
		return true;		
	}

private:
	HCRYPTPROV hCryptProv = NULL;
	LPCSTR UserName = "MyKeyContainer";

#else
#error "Unsupported OS"
#endif
};
