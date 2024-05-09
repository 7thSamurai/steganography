#include <iostream>
#include <fstream>
#include <filesystem>
#include <algorithm>
#include <array>

#include "argparse/argparse.hpp"
#include "aes.hpp"
#include "sha256.hpp"
#include "crc32.hpp"
#include "random.hpp"
#include "image.hpp"
#include "utils.hpp"

#define VERSION 1
#define KEY_ROUNDS 20000
#define LEVEL Image::EncodingLevel::Low

namespace fs = std::filesystem;

// 64 bytes
struct Header {
    // std::uint8_t salt[16];
    // std::uint8_t iv  [16];
    std::uint8_t  sig[4];   // File Signature (HIDE)
    std::uint16_t version;  // Format Version
    std::uint8_t  level;    // Encoding level
    std::uint8_t  flags;    // Flags
    std::uint32_t offset;   // Offset to data
    std::uint32_t size;     // Size of data
    std::uint32_t hash;     // CRC32 hash of data
    std::uint8_t  name[32]; // File name, unused space filled with zeros
    std::uint8_t  reserved[12]; // Must be filled with zeros
};
static_assert(sizeof(Header) == 64);

const char *level_to_str[3] = {
    "Low (Default)",
    "Medium",
    "High"
};

int encode(Image &image, const std::array<std::uint8_t, 32> &password, const std::string &input, const std::string &output, Image::EncodingLevel level) {
    // Open the data file
    std::ifstream file(input, std::ios::in | std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cerr << "ERROR: Unable to open file '" << input << "'" << std::endl;
        return -1;
    }

    std::cout << "* Image size: " << image.w() << "x" << image.h() << " pixels" << std::endl;
    std::cout << "* Encoding level: " << level_to_str[static_cast<int>(level)] << std::endl;

    // Find the data and padded-data size
    std::size_t size = file.tellg();
    std::size_t padded_size = size + 1; // At least one byte of padding
    
    if (padded_size % 16)
        padded_size = (size / 16 + 1) * 16;

    // Find the maximum possible size for the file
    unsigned int max_size = image.w()*image.h()*4/Image::encoded_size(1, level) - Image::encoded_size(sizeof(Header)+32, Image::EncodingLevel::Low); // FIXME

    std::cout << "* Max embed size: " << data_size(max_size) << std::endl;
    std::cout << "* Embed size: " << data_size(size) << std::endl;
    std::cout << "* Encrypted embed size: " << data_size(padded_size) << std::endl;

    // Make sure that it isn't too big
    if (padded_size > max_size) {
        std::cerr << "ERROR: Data-File too big, maximum possible size: " << (max_size / 1024) << " KiB" << std::endl;
        return -1;
    }

    // Read the data
    auto padded_data = std::make_unique<uint8_t[]>(padded_size);
    file.seekg(0, std::ios::beg);
    file.read(reinterpret_cast<char*>(padded_data.get()), size);
    file.close();

    // Pad the data (#PKCS7)
    std::uint8_t left = padded_size - size;
    std::fill_n(padded_data.get() + size, left, left);

    // Pick a random offset inside the image to store the data
    std::uint32_t offset;
    Random random;
    if (!random.get(&offset, sizeof(offset)))
    {
        std::cerr << "Unable to generate random number" << std::endl;
        return -1;
    }

    offset = (offset + Image::encoded_size(sizeof(Header) + 32, Image::EncodingLevel::Low)) % (Image::encoded_size(max_size - padded_size, level));

    // Calculate a hash of the data
    CRC32 crc;
    crc.update(padded_data.get(), size);

    std::cout << "* Generated CRC32 checksum" << std::endl;

    // Copy the header information
    Header header;
    header.sig[0] = 'H'; header.sig[1] = 'I'; header.sig[2] = 'D'; header.sig[3] = 'E';
    header.version = VERSION;
    header.level  = static_cast<std::uint8_t>(level);
    header.flags  = 0;
    header.offset = offset;
    header.size   = padded_size;
    header.hash   = crc.get_hash();

    // Copy the file name to the header
    auto name = fs::path(input).filename().string();
    if (name.size() > sizeof(header.name)) {
        std::cerr << "ERROR: File name '" << name << "' is over 32 characters" << std::endl;
        return -1;
    }
    std::copy_n(name.data(), name.size(), header.name);
    std::fill_n(&header.name[name.size()], sizeof(header.name) - name.size(), 0x00);
    std::fill_n(header.reserved, sizeof(header.reserved), 0x00);

    // Generate the Salt and IV
    std::uint8_t salt[16], iv[16];
    if (!random.get(salt, sizeof salt) || !random.get(iv, sizeof iv))
    {
        std::cerr << "ERROR: Unable to generate random number" << std::endl;
        return -1;
    }

    // Generate the Key
    std::uint8_t key[32];
    pbkdf2_hmac_sha256(password.data(), password.size(), salt, sizeof(salt), key, sizeof(key), KEY_ROUNDS);

    std::cout << "* Generated encryption key with PBKDF2-HMAC-SHA-256 (" << KEY_ROUNDS << " rounds)" << std::endl;

    // Encrypt the header
    AES aes(key, iv);
    auto encrypted_header = std::make_unique<uint8_t[]>(sizeof header);
    aes.cbc_encrypt(&header, sizeof(header), encrypted_header.get());

    // Encrypt the data
    auto encrypted_data = std::make_unique<uint8_t[]>(padded_size);
    aes.cbc_encrypt(padded_data.get(), padded_size, encrypted_data.get());

    std::cout << "* Encrypted embed with AES-256-CBC" << std::endl;

    // Encode the data
    image.encode(salt, 16, level);
    image.encode(iv, 16, level, Image::encoded_size(16, Image::EncodingLevel::Low));
    image.encode(encrypted_header.get(), sizeof(Header), level, Image::encoded_size(32, Image::EncodingLevel::Low));
    image.encode(encrypted_data.get(), padded_size, level, offset);

    std::cout << "* Embedded " << name << " into image" << std::endl;

    // Save the encoded image
    if (!image.save(output)) {
        std::cout << "Unable to save image!" << std::endl;
        return false;
    }

    std::cout << "* Successfully wrote to " << output << std::endl;    

    return true;
}

int decode(Image &image, const std::array<std::uint8_t, 32> &password, std::string output) {
    std::cout << "* Image size: " << image.w() << "x" << image.h() << " pixels" << std::endl;

    // Extract the Salt and IV
    auto salt = image.decode(16, Image::EncodingLevel::Low);
    auto iv   = image.decode(16, Image::EncodingLevel::Low, Image::encoded_size(16, Image::EncodingLevel::Low));

    // Generate the key
    std::uint8_t key[32];
    pbkdf2_hmac_sha256(password.data(), password.size(), salt.get(), 16, key, sizeof(key), KEY_ROUNDS);

    std::cout << "* Generated decryption key with PBKDF2-HMAC-SHA-256 (" << KEY_ROUNDS << " rounds)" << std::endl;

    // Extract the header
    auto encrypted_header = image.decode(sizeof(Header), Image::EncodingLevel::Low, Image::encoded_size(32, Image::EncodingLevel::Low));

    // Decrypt the header
    AES aes(key, iv.get());
    Header header;
    aes.cbc_decrypt(encrypted_header.get(), sizeof(Header), &header);
    auto level = static_cast<Image::EncodingLevel>(header.level);

    // Make sure that the file-signature match, i.e. successful decryption
    if (header.sig[0] != 'H' || header.sig[1] != 'I' || header.sig[2] != 'D' || header.sig[3] != 'E') {
        std::cerr << "ERROR: Decryption failed, invalid key or corrupt file" << std::endl;
        return -1;
    }

    // Make sure that the version is correct
    if (header.version != VERSION) {
        std::cerr << "ERROR: Unsupported file-version " << header.version << std::endl;
        return -1;
    }

    // Make sure that the reserved data is all zeros
    for (auto r : header.reserved) {
        if (r) {
            std::cerr << "ERROR: Decryption failed, invalid key or corrupt file" << std::endl;
            return -1;
        }
    }

    std::cout << "* Successfully decrypted header" << std::endl;
    std::cout << "* File signatures match" << std::endl;

    // Copy the name, accounting for the fact that there might be no null-terminator
    std::string name;
    if (header.name[sizeof(header.name)-1])
        name = std::string(reinterpret_cast<char*>(header.name), sizeof(header.name));
    else
        name = std::string(reinterpret_cast<char*>(header.name));

    std::cout << "* Detected embed " << name << std::endl;
    std::cout << "* Encoding level: " << level_to_str[header.level] << std::endl;

    // Decode the data
    auto encrypted_data = image.decode(header.size, level, header.offset);

    std::cout << "* Encrypted embed size: " << data_size(header.size) << std::endl;

    // Decrypt the data
    auto padded_data = new std::uint8_t[header.size];
    aes.cbc_decrypt(encrypted_data.get(), header.size, padded_data);

    std::cout << "* Successfully decrypted the embed" << std::endl;

    // Find how much padding to strip
    std::uint8_t left = padded_data[header.size - 1];
    std::size_t size  = header.size - left;

    std::cout << "* Decrypted embed size: " << data_size(size) << std::endl;

    // Calculate the CRC32 hash
    CRC32 crc;
    crc.update(padded_data, size);

    // Make sure that the data matches
    if (crc.get_hash() != header.hash) {
        std::cerr << "ERROR: File is corrupted!" << std::endl;
        return -1;
    }

    std::cout << "* CRC32 checksum matches" << std::endl;

    // If the output path is empty, just use the embedded file name
    if (output.empty())
        output = name;

    // Open the output file
    std::ofstream file(output, std::ios::out | std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "ERROR: Unable to save file '" << output << "'" << std::endl;
        return -1;
    }

    // Write the data
    file.write(reinterpret_cast<char*>(padded_data), size);
    file.close();

    delete[] padded_data;

    std::cout << "* Successfully wrote to " << output << std::endl;

    return 0;
}

int main(int argc, char **argv) {
    // Main parser
    argparse::ArgumentParser program("steganography");

    // Encode subcommand
    argparse::ArgumentParser encode_command("encode");
    encode_command.add_description("Encodes an embed-file into an image");

    encode_command.add_argument("-i", "--input")
        .required()
        .help("specify the input image.");

    encode_command.add_argument("-o", "--output")
        .required()
        .help("specify the output image.");

    encode_command.add_argument("-e", "--embed")
        .required()
        .help("specify the file to embed.");

    encode_command.add_argument("-p", "--passwd")
        .help("specify the encryption password.");

    // Decode subcommand
    argparse::ArgumentParser decode_command("decode");
    decode_command.add_description("Decodes and extracts an embed-file from an image");

    decode_command.add_argument("-i", "--input")
        .required()
        .help("specify the input image.");

    decode_command.add_argument("-o", "--output")
        .default_value(std::string(""))
        .help("specify the output file.");

    decode_command.add_argument("-p", "--passwd")
        .help("specify the encryption password.");

    // Add the subcommands to the main parser
    program.add_subparser(encode_command);
    program.add_subparser(decode_command);

    // Parse the arguments
    try {
        program.parse_args(argc, argv);
    }
    catch (const std::runtime_error &err) {
        std::cerr << err.what() << std::endl;
        std::cerr << program;
        return -1;
    }

    // Generates the password hash from a user string
    auto generate_password = [](const argparse::ArgumentParser &parser) -> std::array<std::uint8_t, 32> {
        // Get the password string
        std::string str;
        if (parser.is_used("--passwd")) {
            str = parser.get<std::string>("--passwd");
        }
        else {
            std::cout << "Password: ";
            std::cin >> str;
        }

        // Generate the password hash
        std::array<std::uint8_t, 32> hash;
        SHA256 sha;
        sha.update(str.data(), str.size());
        sha.finish();
        sha.get_hash(hash.data());

        return hash;
    };

    // Encode command
    if (program.is_subcommand_used("encode")) {
        auto input_path  = encode_command.get<std::string>("--input");
        auto output_path = encode_command.get<std::string>("--output");
        auto embed_path  = encode_command.get<std::string>("--embed");

        // Attempt to load the image
        Image image;
        if (!image.load(input_path)) {
            std::cerr << "ERROR: Failed to load image " << input_path << std::endl;
            return -1;
        }

        // Generate the password hash
        auto password = generate_password(encode_command);

        // Encode the image
        if (encode(image, password, embed_path, output_path, LEVEL) < 0)
            return -1;
    }

    // Decode command
    else if (program.is_subcommand_used("decode")) {
        auto input_path  = decode_command.get<std::string>("--input");
        auto output_path = decode_command.get<std::string>("--output");

        // Attempt to load the image
        Image image;
        if (!image.load(input_path)) {
            std::cerr << "ERROR: Failed to load image " << input_path << std::endl;
            return -1;
        }

        // Generate the password hash
        auto password = generate_password(decode_command);

        // Decode the image
        if (decode(image, password, output_path) < 0)
            return -1;
    }

    // No subcommands were given
    else {
        std::cerr << program << std::endl;
    }

    return 0;
}
