#pragma once

#include <cstdint>

#if defined(__APPLE__)
#include <cstddef>
#endif

class CRC32
{
public:
    CRC32();

    void update(const void *data, size_t size);
    std::uint32_t get_hash() const;

private:
    std::uint32_t hash;
};
