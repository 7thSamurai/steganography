#include <iomanip>
#include <algorithm>
#include <cassert>

#include "aes.hpp"
#include "utils.hpp"

// Rijndael S-box
static std::uint8_t sbox[256];
static std::uint8_t inv_sbox[256];

static std::uint8_t mul2 [256];
static std::uint8_t mul3 [256];
static std::uint8_t mul9 [256];
static std::uint8_t mul11[256];
static std::uint8_t mul13[256];
static std::uint8_t mul14[256];

static std::uint8_t rcon[256];

static std::uint8_t gmul(std::uint8_t a, std::uint8_t b) {
    std::uint8_t p = 0;

    for (int i = 0; i < 8; i++) {
        if (b & 1)
            p ^= a;

        bool hi_bit_set = a & 0x80;
        a <<= 1;
        if (hi_bit_set)
            a ^= 0x1b;

        b >>= 1;
    }

    return p;
}

static void build_tables() {
    static bool built_tables = false;
    if (built_tables)
        return;

    built_tables = true;

    // Build the S-box
    std::uint8_t p = 1, q = 1;

    do {
        p = p ^ (p << 1) ^ (p & 0x80 ? 0x1B : 0x00);

        q ^= q << 1;
        q ^= q << 2;
        q ^= q << 4;
        q ^= q & 0x80 ? 0x09 : 0x00;

        std::uint8_t xformed = (q ^ rotl(q, 1) ^ rotl(q, 2) ^ rotl(q, 3) ^ rotl(q, 4)) ^ 0x63;
        sbox[p] = xformed;
        inv_sbox[xformed] = p;
    } while(p != 1);

    sbox    [0x00] = 0x63;
    inv_sbox[0x63] = 0x00;

    // Multiplication Tables
    for (int i = 0; i < 256; i++) {
        mul2 [i] = gmul(i, 2);
        mul3 [i] = gmul(i, 3);
        mul9 [i] = gmul(i, 9);
        mul11[i] = gmul(i, 11);
        mul13[i] = gmul(i, 13);
        mul14[i] = gmul(i, 14);
    }

    for (int i = 1; i < 256; i++) {
        rcon[i] = 1;

        for (int j = i; j != 1; j--)
            rcon[i] = gmul(rcon[i], 2);
    }
}

AES::AES(const std::uint8_t *key, const std::uint8_t *iv) {
    build_tables();
    expand_key(key);

    std::copy_n(iv, block_len, this->iv);
}

void AES::cbc_encrypt(void *data, std::size_t size, void *result) {
    assert(size % block_len == 0);
    auto in  = static_cast<std::uint8_t*>(data);
    auto out = static_cast<std::uint8_t*>(result);
    std::uint8_t *iv = this->iv;

    for (std::size_t i = 0; i < size; i += block_len) {
        xor_with_iv(in, iv);
        encrypt_block(in, out);

        iv = out;
        in  += block_len;
        out += block_len;
    }

    std::copy_n(iv, block_len, this->iv);
}

void AES::cbc_decrypt(void *data, std::size_t size, void *result) {
    assert(size % block_len == 0);
    auto in  = static_cast<std::uint8_t*>(data);
    auto out = static_cast<std::uint8_t*>(result);
    std::uint8_t *iv = this->iv;

    for (std::size_t i = 0; i < size; i += block_len) {
        decrypt_block(in, out);
        xor_with_iv(out, iv);

        iv = in;
        in  += block_len;
        out += block_len;
    }

    std::copy_n(iv, block_len, this->iv);
}

inline void AES::add_round_key(State state, const State round_key, int round) {
    for (int i = 0; i < 0x10; i++)
        state[i] ^= round_key[(round * 16) + i];
}

inline void AES::sub_bytes(State state) {
    for (int i = 0; i < 0x10; i++)
        state[i] = sbox[state[i]];
}

inline void AES::shift_rows(State state) {
    State tmp;

    // Column 1
    tmp[0x00] = state[0x00];
    tmp[0x01] = state[0x05];
    tmp[0x02] = state[0x0a];
    tmp[0x03] = state[0x0f];

    // Column 2
    tmp[0x04] = state[0x04];
    tmp[0x05] = state[0x09];
    tmp[0x06] = state[0x0e];
    tmp[0x07] = state[0x03];

    // Column 3
    tmp[0x08] = state[0x08];
    tmp[0x09] = state[0x0d];
    tmp[0x0a] = state[0x02];
    tmp[0x0b] = state[0x07];

    // Column 4
    tmp[0x0c] = state[0x0c];
    tmp[0x0d] = state[0x01];
    tmp[0x0e] = state[0x06];
    tmp[0x0f] = state[0x0b];

    std::copy_n(tmp, block_len, state);
}

inline void AES::mix_columns(State state) {
    State tmp;

    // Column 1
    tmp[0x00] = mul2[state[0]] ^ mul3[state[1]] ^ state[2] ^ state[3];
    tmp[0x01] = state[0] ^ mul2[state[1]] ^ mul3[state[2]] ^ state[3];
    tmp[0x02] = state[0] ^ state[1] ^ mul2[state[2]] ^ mul3[state[3]];
    tmp[0x03] = mul3[state[0]] ^ state[1] ^ state[2] ^ mul2[state[3]];

    // Column 2
    tmp[0x04] = mul2[state[4]] ^ mul3[state[5]] ^ state[6] ^ state[7];
    tmp[0x05] = state[4] ^ mul2[state[5]] ^ mul3[state[6]] ^ state[7];
    tmp[0x06] = state[4] ^ state[5] ^ mul2[state[6]] ^ mul3[state[7]];
    tmp[0x07] = mul3[state[4]] ^ state[5] ^ state[6] ^ mul2[state[7]];

    // Column 3
    tmp[0x08] = mul2[state[8]] ^ mul3[state[9]] ^ state[10] ^ state[11];
    tmp[0x09] = state[8] ^ mul2[state[9]] ^ mul3[state[10]] ^ state[11];
    tmp[0x0a] = state[8] ^ state[9] ^ mul2[state[10]] ^ mul3[state[11]];
    tmp[0x0b] = mul3[state[8]] ^ state[9] ^ state[10] ^ mul2[state[11]];

    // Column 4
    tmp[0x0c] = mul2[state[12]] ^ mul3[state[13]] ^ state[14] ^ state[15];
    tmp[0x0d] = state[12] ^ mul2[state[13]] ^ mul3[state[14]] ^ state[15];
    tmp[0x0e] = state[12] ^ state[13] ^ mul2[state[14]] ^ mul3[state[15]];
    tmp[0x0f] = mul3[state[12]] ^ state[13] ^ state[14] ^ mul2[state[15]];

    std::copy_n(tmp, block_len, state);
}

inline void AES::inverse_sub_bytes(State state) {
    for (int i = 0; i < 0x10; i++)
        state[i] = inv_sbox[state[i]];
}

inline void AES::inverse_shift_rows(State state) {
    State tmp;

    // Column 1
    tmp[0x00] = state[0x00];
    tmp[0x01] = state[0x0d];
    tmp[0x02] = state[0x0a];
    tmp[0x03] = state[0x07];

    // Column 2
    tmp[0x04] = state[0x04];
    tmp[0x05] = state[0x01];
    tmp[0x06] = state[0x0e];
    tmp[0x07] = state[0x0b];

    // Column 3
    tmp[0x08] = state[0x08];
    tmp[0x09] = state[0x05];
    tmp[0x0a] = state[0x02];
    tmp[0x0b] = state[0x0f];

    // Column 4
    tmp[0x0c] = state[0x0c];
    tmp[0x0d] = state[0x09];
    tmp[0x0e] = state[0x06];
    tmp[0x0f] = state[0x03];

    std::copy_n(tmp, block_len, state);
}

inline void AES::inverse_mix_columns(State state) {
    State tmp;

    tmp[0x00] = mul14[state[0]] ^ mul11[state[1]] ^ mul13[state[2]] ^ mul9[state[3]];
    tmp[0x01] = mul9[state[0]] ^ mul14[state[1]] ^ mul11[state[2]] ^ mul13[state[3]];
    tmp[0x02] = mul13[state[0]] ^ mul9[state[1]] ^ mul14[state[2]] ^ mul11[state[3]];
    tmp[0x03] = mul11[state[0]] ^ mul13[state[1]] ^ mul9[state[2]] ^ mul14[state[3]];

    tmp[0x04] = mul14[state[4]] ^ mul11[state[5]] ^ mul13[state[6]] ^ mul9[state[7]];
    tmp[0x05] = mul9[state[4]] ^ mul14[state[5]] ^ mul11[state[6]] ^ mul13[state[7]];
    tmp[0x06] = mul13[state[4]] ^ mul9[state[5]] ^ mul14[state[6]] ^ mul11[state[7]];
    tmp[0x07] = mul11[state[4]] ^ mul13[state[5]] ^ mul9[state[6]] ^ mul14[state[7]];

    tmp[0x08] = mul14[state[8]] ^ mul11[state[9]] ^ mul13[state[10]] ^ mul9[state[11]];
    tmp[0x09] = mul9[state[8]] ^ mul14[state[9]] ^ mul11[state[10]] ^ mul13[state[11]];
    tmp[0x0a] = mul13[state[8]] ^ mul9[state[9]] ^ mul14[state[10]] ^ mul11[state[11]];
    tmp[0x0b] = mul11[state[8]] ^ mul13[state[9]] ^ mul9[state[10]] ^ mul14[state[11]];

    tmp[0x0c] = mul14[state[12]] ^ mul11[state[13]] ^ mul13[state[14]] ^ mul9[state[15]];
    tmp[0x0d] = mul9[state[12]] ^ mul14[state[13]] ^ mul11[state[14]] ^ mul13[state[15]];
    tmp[0x0e] = mul13[state[12]] ^ mul9[state[13]] ^ mul14[state[14]] ^ mul11[state[15]];
    tmp[0x0f] = mul11[state[12]] ^ mul13[state[13]] ^ mul9[state[14]] ^ mul14[state[15]];

    std::copy_n(tmp, block_len, state);
}

inline void AES::xor_with_iv(std::uint8_t *data, const std::uint8_t *iv) {
    for (std::size_t i = 0; i < block_len; i++)
        data[i] ^= iv[i];
}

void AES::encrypt_block(const std::uint8_t *in, std::uint8_t *out) {
    State state;
    std::copy_n(in, block_len, state);

    add_round_key(state, expanded_key, 0);
    for (int i = 0; i < 13; i++) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, expanded_key, i+1);
    }

    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, expanded_key, 14);

    std::copy_n(state, block_len, out);
}

void AES::decrypt_block(const std::uint8_t *in, std::uint8_t *out) {
    State state;
    std::copy_n(in, block_len, state);

    add_round_key(state, expanded_key, 14);
    for (int i = 12; i >= 0; i--) {
        inverse_shift_rows(state);
        inverse_sub_bytes(state);
        add_round_key(state, expanded_key, i+1);
        inverse_mix_columns(state);
    }

    inverse_shift_rows(state);
    inverse_sub_bytes(state);
    add_round_key(state, expanded_key, 0);

    std::copy_n(state, block_len, out);
}

void AES::schedule_core(std::uint8_t *in, unsigned int i) {
    std::uint8_t t = in[0];
    in[0] = in[1];
    in[1] = in[2];
    in[2] = in[3];
    in[3] = t;

    in[0] = sbox[in[0]];
    in[1] = sbox[in[1]];
    in[2] = sbox[in[2]];
    in[3] = sbox[in[3]];

    in[0] ^= rcon[i];
}

void AES::expand_key(const std::uint8_t *in) {
    std::copy_n(in, 32, expanded_key);

    std::uint8_t t[4];
    std::uint8_t c = 32;
    std::uint8_t i = 1;

    while (c < 240) {
        for (int a = 0; a < 4; a++)
            t[a] = expanded_key[a + c - 4];

        if ((c & 31) == 0)
            schedule_core(t, i++);

        if ((c & 31) == 16) {
            for (int a = 0; a < 4; a++)
                t[a] = sbox[t[a]];
        }

        for (int a = 0; a < 4; a++) {
            expanded_key[c] = expanded_key[c - 32] ^ t[a];
            c++;
        }
    }
}
