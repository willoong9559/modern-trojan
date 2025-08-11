#include "hash.h"

#include <cassert>
#include <cstring>
#include "fmt/core.h"
#include "fmt/ranges.h"
#include "range/v3/all.hpp"

using ranges::views::take;

namespace hash {
    namespace {
        // SHA-224/256 constants
        constexpr array<uint32_t, 64> K = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
            0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
            0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
            0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        };

        // Right rotate
        constexpr uint32_t rotr(uint32_t x, int n) noexcept {
            return (x >> n) | (x << (32 - n));
        }

        // SHA-256 functions
        constexpr uint32_t ch(uint32_t x, uint32_t y, uint32_t z) noexcept {
            return (x & y) ^ (~x & z);
        }

        constexpr uint32_t maj(uint32_t x, uint32_t y, uint32_t z) noexcept {
            return (x & y) ^ (x & z) ^ (y & z);
        }

        constexpr uint32_t sigma0(uint32_t x) noexcept {
            return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
        }

        constexpr uint32_t sigma1(uint32_t x) noexcept {
            return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
        }

        constexpr uint32_t gamma0(uint32_t x) noexcept {
            return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
        }

        constexpr uint32_t gamma1(uint32_t x) noexcept {
            return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
        }

        // Convert big-endian bytes to uint32_t
        uint32_t bytes_to_word(const uint8_t* bytes) noexcept {
            return (static_cast<uint32_t>(bytes[0]) << 24) |
                   (static_cast<uint32_t>(bytes[1]) << 16) |
                   (static_cast<uint32_t>(bytes[2]) << 8) |
                   static_cast<uint32_t>(bytes[3]);
        }

        // Convert uint32_t to big-endian bytes
        void word_to_bytes(uint32_t word, uint8_t* bytes) noexcept {
            bytes[0] = static_cast<uint8_t>(word >> 24);
            bytes[1] = static_cast<uint8_t>(word >> 16);
            bytes[2] = static_cast<uint8_t>(word >> 8);
            bytes[3] = static_cast<uint8_t>(word);
        }
    }

    Hasher::Hasher() : total_len(0), buffer_len(0), finalized(false) {
        // SHA-224 initial hash values (different from SHA-256)
        h[0] = 0xc1059ed8;
        h[1] = 0x367cd507;
        h[2] = 0x3070dd17;
        h[3] = 0xf70e5939;
        h[4] = 0xffc00b31;
        h[5] = 0x68581511;
        h[6] = 0x64f98fa7;
        h[7] = 0xbefa4fa4;
        
        buffer.fill(0);
    }

    int Hasher::update(const uint8_t *src, int len) noexcept {
        if (finalized || src == nullptr || len < 0) {
            return 0; // Error
        }

        const uint8_t* data = src;
        size_t remaining = static_cast<size_t>(len);
        total_len += len;

        // If we have data in buffer, try to fill it first
        if (buffer_len > 0) {
            size_t to_copy = std::min(remaining, 64 - buffer_len);
            std::memcpy(buffer.data() + buffer_len, data, to_copy);
            buffer_len += to_copy;
            data += to_copy;
            remaining -= to_copy;

            // If buffer is full, process it
            if (buffer_len == 64) {
                process_block(buffer.data());
                buffer_len = 0;
            }
        }

        // Process complete 64-byte blocks
        while (remaining >= 64) {
            process_block(data);
            data += 64;
            remaining -= 64;
        }

        // Store remaining data in buffer
        if (remaining > 0) {
            std::memcpy(buffer.data(), data, remaining);
            buffer_len = remaining;
        }

        return 1; // Success
    }

    int Hasher::finalize(uint8_t *dst, int *len) noexcept {
        if (finalized || dst == nullptr || len == nullptr) {
            return 0; // Error
        }

        pad_and_process();
        finalized = true;

        // Copy hash to output (28 bytes for SHA-224)
        for (int i = 0; i < 7; ++i) {
            word_to_bytes(h[i], dst + i * 4);
        }

        *len = 28; // SHA-224 produces 28 bytes (224 bits)
        return 1; // Success
    }

    void Hasher::process_block(const uint8_t* block) noexcept {
        array<uint32_t, 64> w;
        
        // Prepare message schedule
        for (int i = 0; i < 16; ++i) {
            w[i] = bytes_to_word(block + i * 4);
        }
        
        for (int i = 16; i < 64; ++i) {
            w[i] = gamma1(w[i-2]) + w[i-7] + gamma0(w[i-15]) + w[i-16];
        }

        // Initialize working variables
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
        uint32_t e = h[4], f = h[5], g = h[6], h_var = h[7];

        // Main loop
        for (int i = 0; i < 64; ++i) {
            uint32_t t1 = h_var + sigma1(e) + ch(e, f, g) + K[i] + w[i];
            uint32_t t2 = sigma0(a) + maj(a, b, c);
            
            h_var = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }

        // Update hash values
        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += h_var;
    }

    void Hasher::pad_and_process() noexcept {
        uint64_t total_bits = total_len * 8;
        
        // Add padding bit (0x80)
        buffer[buffer_len++] = 0x80;
        
        // If not enough space for length, pad to end and process
        if (buffer_len > 56) {
            while (buffer_len < 64) {
                buffer[buffer_len++] = 0;
            }
            process_block(buffer.data());
            buffer_len = 0;
        }
        
        // Pad with zeros up to 56 bytes
        while (buffer_len < 56) {
            buffer[buffer_len++] = 0;
        }
        
        // Append original length in bits as big-endian 64-bit
        for (int i = 7; i >= 0; --i) {
            buffer[56 + (7-i)] = static_cast<uint8_t>(total_bits >> (i * 8));
        }
        
        process_block(buffer.data());
    }

    array<uint8_t, 56> sha224(const uint8_t *src, int len) noexcept {
        Hasher hasher{};
        array<uint8_t, 56> hex{0};
        array<uint8_t, 28> hash_result{0};
        int hash_len = 0;

        hasher.update(src, len);
        hasher.finalize(hash_result.data(), &hash_len);

        // Convert to hex string
        int offset = 0;
        for (auto b : hash_result) {
            fmt::format_to(hex.data() + offset, "{:02x}", b);
            offset += 2;
        }
        
        return hex;
    }
}
