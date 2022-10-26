#include "random.hpp"

#if defined(__linux__) || defined(__APPLE__)
Random::Random() {
    file = fopen("/dev/urandom", "rb");
}

Random::~Random() {
    if (file)
        fclose(file);
}

void Random::get(void *data, std::size_t size) {
    fread(data, size, 1, file);
}
#else
#error "Unsupported OS"
#endif
