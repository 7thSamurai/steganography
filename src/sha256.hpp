#pragma once

#include <cstdint>
#include <string>

class SHA256
{
public:
    SHA256();

    void update(const void *data, std::size_t size);
    void finish();
    void get_hash(std::uint8_t hash[32]) const;

private:
    void process_chunk(const std::uint8_t *data);

    std::uint32_t h[8];
    std::uint64_t data_size;

    // The left-over data
    std::uint64_t last_size;
    std::uint8_t last_data[64];
};

void hmac_sha256(const void *data, std::size_t size, const void *key, std::size_t key_size, std::uint8_t hash[32]);
void pbkdf2_hmac_sha256(const void *pass, std::size_t pass_size, const void *salt, std::size_t salt_size, void *result, std::size_t result_size, std::size_t rounds);
