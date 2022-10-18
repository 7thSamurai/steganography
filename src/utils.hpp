#pragma once

#include <string>
#include <sstream>
#include <iomanip>

inline std::string data_size(std::size_t size) {
    std::stringstream ss;

    if (size >= 1024*1024)
        ss << std::fixed << std::setprecision(2) << size / float(1024*1024) << " MiB";
    else if (size >= 1024)
        ss << std::fixed << std::setprecision(2) << size / float(1024) << " KiB";
    else
        ss << size << " B";

    return ss.str();
}

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
