#pragma once

#include <cstdint>

class AES
{
public:
    // Note: Never use the same IV with the same key
    AES(const std::uint8_t *key, const std::uint8_t *iv);

	// All data must be padded to be a multiple of 16-bytes. Try #PKCS7
    void cbc_encrypt(void *data, std::size_t size, void *result);
    void cbc_decrypt(void *data, std::size_t size, void *result);

private:
    using State = std::uint8_t[16];

    static const unsigned int block_len = 16; // 128 bits

    inline void add_round_key(State state, const State round_key, int round);
    inline void sub_bytes(State state);
    inline void shift_rows(State state);
    inline void mix_columns(State state);

    inline void inverse_sub_bytes(State state);
    inline void inverse_shift_rows(State state);
    inline void inverse_mix_columns(State state);

    inline void xor_with_iv(std::uint8_t *data, const std::uint8_t *iv);

    void encrypt_block(const std::uint8_t *in, std::uint8_t *out);
    void decrypt_block(const std::uint8_t *in, std::uint8_t *out);

    void schedule_core(std::uint8_t *in, unsigned int i);
    void expand_key(const std::uint8_t *in);

    std::uint8_t expanded_key[240];
    std::uint8_t iv[block_len];
};
