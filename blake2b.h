//
// Created by Kaan Karaman on 10/12/2024.
//

#ifndef MD5ANDARGON2_BLAKE2B_H
#define MD5ANDARGON2_BLAKE2B_H

#include <cstdint>
#include <string>

class Blake2b {
public:
    static const size_t HashSize = 64; // Blake2b produces a 512-bit hash

    explicit Blake2b(size_t outputSize = HashSize);

    void update(const void* data, size_t len);
    void finalize(void* out);

    static std::string hash(const std::string& input, size_t outputSize = HashSize);

private:
    void compress(const uint8_t* block);
    void initialize();

    static const size_t BlockSize = 128; // Block size in bytes
    static const uint64_t IV[8];         // Initialization vector

    uint8_t buffer_[BlockSize]{};
    size_t bufferLength_;
    uint64_t h_[8]{};      // Chained state
    uint64_t t_[2]{};      // Counter
    uint64_t f_[2]{};      // Finalization flag
    size_t outputSize_;  // Desired hash output size
};

#endif //MD5ANDARGON2_BLAKE2B_H
