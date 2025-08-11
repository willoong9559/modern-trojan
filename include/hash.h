#pragma once

#include <cstdint>
#include <array>

using std::array;

namespace hash {
    struct Hasher {
        Hasher();
        Hasher(const Hasher&) = delete;
        Hasher(Hasher&&) = delete;
        Hasher& operator=(const Hasher&) = delete;
        Hasher& operator=(Hasher&&) = delete;
        ~Hasher() = default;
        int update(const uint8_t *src, int len) noexcept;
        int finalize(uint8_t *dst, int *len) noexcept;

    private:
        // SHA-224 uses same algorithm as SHA-256 but different initial values
        array<uint32_t, 8> h;
        array<uint8_t, 64> buffer;
        uint64_t total_len;
        size_t buffer_len;
        bool finalized;

        void process_block(const uint8_t* block) noexcept;
        void pad_and_process() noexcept;
    };

    array<uint8_t, 56> sha224(const uint8_t *src, int len) noexcept;
}
