#pragma once

#include <cstdint>

class CRC32
{
public:
    CRC32();

    void update(const void *data, std::size_t size);
    std::uint32_t get_hash() const;

private:
    std::uint32_t hash;
};
