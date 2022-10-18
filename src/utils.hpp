#pragma once

// Rotate bits left shift places
template <typename T> T rotl(const T &t, std::size_t shift) {
    constexpr std::size_t bits = sizeof(T) * 8;
    return (t << shift) | (t >> (bits - shift));
}

// Rotate bits right shift places
template <typename T> T rotr(const T &t, std::size_t shift) {
    constexpr std::size_t bits = sizeof(T) * 8;
    return (t >> shift) | (t << (bits - shift));
}
