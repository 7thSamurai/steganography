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
		return fread(data, size, 1, file) == size;
	}

private:
	FILE* file;

#elif defined(_WIN32)
public:
	Random()  = default;
	~Random() = default;

	bool get(void* data, std::size_t size) {
		auto status = BCryptGenRandom(
			NULL,
			(BYTE*)data,
			size,
			BCRYPT_USE_SYSTEM_PREFERRED_RNG);

		if (!BCRYPT_SUCCESS(status))
		{
			std::cerr << "ERROR: Unable to generate random number" << std::endl;
			return false;
		}
		return true;
	}

#else
#error "Unsupported OS"
#endif
};
