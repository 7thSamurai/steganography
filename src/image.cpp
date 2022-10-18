#include "image.hpp"
#include "stb/stb_image.h"
#include "stb/stb_image_write.h"

#include <algorithm>

Image::Image() : width(0), height(0) {
}

bool Image::load(const std::string &path) {
    int x, y, n = 4;

    auto *buffer = stbi_load(path.c_str(), &x, &y, &n, n);
    if (!image)
        return false;

    image = std::make_unique<std::uint8_t[]>(x * y * 4);
    std::copy_n(buffer, x * y * 4, image.get());
    stbi_image_free(buffer);

    width  = x;
    height = y;

    return true;
}

bool Image::save(const std::string &path) {
    int result = stbi_write_png(path.c_str(), width, height, 4, image.get(), width * 4);

    return result != 0;
}

void Image::encode(const std::uint8_t *data, std::size_t size, EncodingLevel level) {
    auto image = this->image.get();

    if (level == EncodingLevel::Low) {
        for (auto i = 0; i < size; i++, image += 8) {
            image[0] = (image[0] & ~0b1) | ((data[i] >> 0) & 0b1);
            image[1] = (image[1] & ~0b1) | ((data[i] >> 1) & 0b1);
            image[2] = (image[2] & ~0b1) | ((data[i] >> 2) & 0b1);
            image[3] = (image[3] & ~0b1) | ((data[i] >> 3) & 0b1);
            image[4] = (image[4] & ~0b1) | ((data[i] >> 4) & 0b1);
            image[5] = (image[5] & ~0b1) | ((data[i] >> 5) & 0b1);
            image[6] = (image[6] & ~0b1) | ((data[i] >> 6) & 0b1);
            image[7] = (image[7] & ~0b1) | ((data[i] >> 7) & 0b1);
        }
    }

    else if (level == EncodingLevel::Med) {
        for (auto i = 0; i < size; i++, image += 4) {
            image[0] = (image[0] & ~0b11) | ((data[i] >> 0) & 0b11);
            image[1] = (image[1] & ~0b11) | ((data[i] >> 2) & 0b11);
            image[2] = (image[2] & ~0b11) | ((data[i] >> 4) & 0b11);
            image[3] = (image[3] & ~0b11) | ((data[i] >> 6) & 0b11);
        }
    }

    // High
    else {
        for (auto i = 0; i < size / 2; i++, image += 4, data += 2) {
            image[0] = (image[0] & ~0xf) | (data[0] & 0xf);
            image[1] = (image[1] & ~0xf) | (data[0] >> 4);
            image[2] = (image[2] & ~0xf) | (data[1] & 0xf);
            image[3] = (image[3] & ~0xf) | (data[1] >> 4);
        }

        if (size % 2) {
            image[0] = (image[0] & ~0xf) | (*data & 0xf);
            image[1] = (image[1] & ~0xf) | (*data >> 4);
        }
    }
}

std::unique_ptr<std::uint8_t[]> Image::decode(std::size_t size, EncodingLevel level) {
    auto data  = std::make_unique<std::uint8_t[]>(size);
    auto image = this->image.get();

    if (level == EncodingLevel::Low) {
        for (auto i = 0; i < size; i++, image += 8) {
            data[i] = ((image[0] & 0b1) << 0) | ((image[1] & 0b1) << 1) |
                      ((image[2] & 0b1) << 2) | ((image[3] & 0b1) << 3) |
                      ((image[4] & 0b1) << 4) | ((image[5] & 0b1) << 5) |
                      ((image[6] & 0b1) << 6) | ((image[7] & 0b1) << 7);
        }
    }

    else if (level == EncodingLevel::Med) {
        for (auto i = 0; i < size; i++, image += 4) {
            data[i] = ((image[0] & 0b11) << 0) | ((image[1] & 0b11) << 2) |
                      ((image[2] & 0b11) << 4) | ((image[3] & 0b11) << 6);
        }
    }

    // High
    else {
        auto buffer = data.get();

        for (auto i = 0; i < size / 2; i++, image += 4, buffer += 2) {
            buffer[0] = (image[0] & 0xf) | (image[1] << 4);
            buffer[1] = (image[2] & 0xf) | (image[3] << 4);
        }

        if (size % 2)
            *buffer = (image[0] & 0xf) | (image[1] << 4);
    }

    return data;
}

std::size_t Image::encoded_size(std::size_t size, EncodingLevel level) {
    if (level == EncodingLevel::Low)
        return size * 8;

    else if (level == EncodingLevel::Med)
        return size * 4;

    // High
    return size * 2;
}
