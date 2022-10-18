#include "sha256.hpp"
#include "hide.hpp"

#include <sstream>
#include <iomanip>
#include <algorithm>

static const std::uint32_t k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};


SHA256::SHA256() {
    h[0] = 0x6a09e667;
    h[1] = 0xbb67ae85;
    h[2] = 0x3c6ef372;
    h[3] = 0xa54ff53a;
    h[4] = 0x510e527f;
    h[5] = 0x9b05688c;
    h[6] = 0x1f83d9ab;
    h[7] = 0x5be0cd19;

    data_size = 0;
    last_size = 0;
}

void SHA256::update(const void *data, std::size_t size) {
    auto *buffer = static_cast<const std::uint8_t*>(data);
    data_size += size * 8;

    // Use up the left-over data from last time
    if (size + last_size >= 64) {
        std::uint64_t need = 64 - last_size;
        std::copy(buffer, buffer + need, last_data + last_size);

        buffer += need;
        size   -= need;

        last_size = 0;
        process_chunk(last_data);
    }

    while (size >= 64) {
        process_chunk(buffer);

        buffer += 64;
        size   -= 64;
    }

    std::copy(buffer, buffer + size, last_data + last_size);
    last_size += size;
}

void SHA256::finish() {
    last_data[last_size++] = 0x80;
    std::fill(last_data + last_size, last_data + 64, 0);

    if (last_size > 56) {
        process_chunk(last_data);
        std::fill(last_data, last_data + 64, 0);
    }

    for (int i = 8; i > 0; i--) {
        last_data[55+i] = data_size & 0xff;
        data_size >>= 8;
    }

    process_chunk(last_data);
}

void SHA256::get_hash(std::uint8_t hash[32]) const {
    for (int i = 0; i < 8; i++) {
        hash[i*4+0] = (h[i] >> 24) & 0xff;
        hash[i*4+1] = (h[i] >> 16) & 0xff;
        hash[i*4+2] = (h[i] >> 8)  & 0xff;
        hash[i*4+3] = (h[i] >> 0)  & 0xff;
    }
}

void SHA256::process_chunk(const std::uint8_t *data) {
    std::uint32_t w[64];

    for (int i = 0; i < 16; i++) {
        w[i] = data[0] << 24 | data[1] << 16 | data[2] << 8 | data[3];
        data += 4;
    }

    for (int i = 16; i < 64; i++) {
        std::uint32_t s0 = rotr(w[i-15],  7) ^ rotr(w[i-15], 18) ^ (w[i-15] >>  3);
        std::uint32_t s1 = rotr(w[i- 2], 17) ^ rotr(w[i- 2], 19) ^ (w[i- 2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }

    std::uint32_t tv[8];
    std::copy(h, h+8, tv);

    for (int i = 0; i < 64; i++) {
        std::uint32_t S1 = rotr(tv[4], 6) ^ rotr(tv[4], 11) ^ rotr(tv[4], 25);
        std::uint32_t ch = (tv[4] & tv[5]) ^ ((~tv[4]) & tv[6]);
        std::uint32_t temp1 = tv[7] + S1 + ch + k[i] + w[i];
        std::uint32_t S0 = rotr(tv[0], 2) ^ rotr(tv[0], 13) ^ rotr(tv[0], 22);
        std::uint32_t maj = (tv[0] & tv[1]) ^ (tv[0] & tv[2]) ^ (tv[1] & tv[2]);
        std::uint32_t temp2 = S0 + maj;

        tv[7] = tv[6];
        tv[6] = tv[5];
        tv[5] = tv[4];
        tv[4] = tv[3] + temp1;
        tv[3] = tv[2];
        tv[2] = tv[1];
        tv[1] = tv[0];
        tv[0] = temp1 + temp2;
    }

    for (int i = 0; i < 8; i++)
        h[i] += tv[i];
}


static void H(const void *data1, std::size_t size1, const void *data2, std::size_t size2, std::uint8_t hash[32]) {  
    SHA256 sha;
    sha.update(data1, size1);
    sha.update(data2, size2);
    sha.finish();
    sha.get_hash(hash);
}

void hmac_sha256(const void *data, std::size_t size, const void *key, std::size_t key_size, std::uint8_t hash[32]) {
    std::uint8_t K[64];
    std::fill_n(K, 64, 0x00);
    
    if (key_size <= 64)
        std::copy_n(static_cast<const std::uint8_t*>(key), key_size, K);
    
    else if (key_size > 64) {
        SHA256 sha;
        sha.update(key, key_size);
        sha.finish();
        sha.get_hash(K);    
    }
    
    std::uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; i++) {
        ipad[i] = K[i] ^ 0x36;
        opad[i] = K[i] ^ 0x5c;
    }
    
    std::uint8_t ihash[32];
    H(ipad, 64, data, size, ihash);
    H(opad, 64, ihash, 32, hash);
}

void pbkdf2_hmac_sha256(const void *pass, std::size_t pass_size, const void *salt, std::size_t salt_size, void *result, std::size_t result_size, std::size_t rounds) {
    std::uint8_t u1[32], u2[32], f[32];
    std::uint8_t *s = new std::uint8_t[salt_size + 4];
    std::uint8_t *r = static_cast<std::uint8_t*>(result);
    
    std::copy_n(static_cast<const std::uint8_t*>(salt), salt_size, s);
    
    for (std::size_t count = 1; result_size > 0; count++) {
        s[salt_size+0] = (count >> 24) & 0xff;
        s[salt_size+1] = (count >> 16) & 0xff;
        s[salt_size+2] = (count >> 8)  & 0xff;
        s[salt_size+3] = (count >> 0)  & 0xff;
        
        hmac_sha256(s, salt_size + 4, pass, pass_size, u1);
        std::copy_n(u1, sizeof(u1), f);
        
        for (std::size_t i = 1; i < rounds; i++) {
            hmac_sha256(u1, sizeof(u1), pass, pass_size, u2);
            std::copy_n(u2, sizeof(u2), u1);
            
            for (std::size_t j = 0; j < sizeof(f); j++)
                f[j] ^= u2[j];
        }
        
        std::size_t size = std::min(result_size, (std::size_t)32);
        std::copy_n(f, size, r);
            
        r += size;
        result_size -= size;
    }

    delete[] s;
}
