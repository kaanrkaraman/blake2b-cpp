//
// Created by Kaan Karaman on 10/12/2024.
//

#include "blake2b.h"
#include <cstring>
#include <sstream>
#include <iomanip>

// Initialization vector (IV) constants (from the Blake2b specification)
const uint64_t Blake2b::IV[8] = {
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
        0x510e527fade682d1, 0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
};

// Sigma permutation table
static const uint8_t Sigma[12][16] = {
        { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
        { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
        { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
        { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
        { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
        { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
        { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
        { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
        { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
        { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
        { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
        { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 }
};

Blake2b::Blake2b(size_t outputSize)
        : bufferLength_(0), outputSize_(outputSize) {
    initialize();
}

void Blake2b::initialize() {
    std::memcpy(h_, IV, sizeof(IV));
    h_[0] ^= 0x01010000 | (outputSize_ & 0xFF);
    t_[0] = t_[1] = 0;
    f_[0] = f_[1] = 0;
}

// G is a compression function
#define G(v, a, b, c, d, x, y) \
    do { \
        v[a] += v[b] + x; \
        v[d] ^= v[a]; \
        v[d] = (v[d] >> 32) | (v[d] << 32); \
        v[c] += v[d]; \
        v[b] ^= v[c]; \
        v[b] = (v[b] >> 24) | (v[b] << 40); \
        v[a] += v[b] + y; \
        v[d] ^= v[a]; \
        v[d] = (v[d] >> 16) | (v[d] << 48); \
        v[c] += v[d]; \
        v[b] ^= v[c]; \
        v[b] = (v[b] >> 63) | (v[b] << 1); \
    } while (0)

void Blake2b::compress(const uint8_t* block) {
    uint64_t v[16], m[16];
    std::memcpy(v, h_, sizeof(h_));
    std::memcpy(v + 8, IV, sizeof(IV));
    v[12] ^= t_[0];
    v[13] ^= t_[1];
    v[14] ^= f_[0];
    v[15] ^= f_[1];

    for (size_t i = 0; i < 16; ++i) {
        m[i] = ((uint64_t)block[i * 8 + 0]) |
               ((uint64_t)block[i * 8 + 1] << 8) |
               ((uint64_t)block[i * 8 + 2] << 16) |
               ((uint64_t)block[i * 8 + 3] << 24) |
               ((uint64_t)block[i * 8 + 4] << 32) |
               ((uint64_t)block[i * 8 + 5] << 40) |
               ((uint64_t)block[i * 8 + 6] << 48) |
               ((uint64_t)block[i * 8 + 7] << 56);
    }

    for (const uint8_t (&s)[16] : Sigma) {
        G(v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        G(v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        G(v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        G(v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        G(v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        G(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        G(v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        G(v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }

    for (size_t i = 0; i < 8; ++i) {
        h_[i] ^= v[i] ^ v[i + 8];
    }
}

void Blake2b::update(const void* data, size_t len) {
    const auto* input = static_cast<const uint8_t*>(data);

    while (len > 0) {
        size_t toFill = BlockSize - bufferLength_;
        size_t copySize = (len < toFill) ? len : toFill;

        std::memcpy(buffer_ + bufferLength_, input, copySize);
        bufferLength_ += copySize;
        input += copySize;
        len -= copySize;

        if (bufferLength_ == BlockSize) {
            compress(buffer_);
            t_[0] += BlockSize;
            bufferLength_ = 0;
        }
    }
}

void Blake2b::finalize(void* out) {
    t_[0] += bufferLength_;
    f_[0] = ~0ULL;

    std::memset(buffer_ + bufferLength_, 0, BlockSize - bufferLength_);
    compress(buffer_);

    std::memcpy(out, h_, outputSize_);
}

std::string Blake2b::hash(const std::string& input, size_t outputSize) {
    Blake2b blake(outputSize);
    blake.update(input.data(), input.size());

    uint8_t out[HashSize];
    blake.finalize(out);

    std::ostringstream oss;
    for (size_t i = 0; i < outputSize; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(out[i]);
    }
    return oss.str();
}