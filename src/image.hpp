#pragma once

#include <cstdint>
#include <string>
#include <memory>

class Image
{
public:
    enum class EncodingLevel {
        Low  = 0,
        Med  = 1,
        High = 2,
    };

    Image();

    bool load(const std::string &path);
    bool save(const std::string &path);

    void encode(const std::uint8_t *data, std::size_t size, EncodingLevel level);
    std::unique_ptr<std::uint8_t[]> decode(std::size_t size, EncodingLevel level);

    std::size_t encoded_size(std::size_t size, EncodingLevel level);

private:
    std::unique_ptr<std::uint8_t[]> image;
    unsigned int width, height;
};
