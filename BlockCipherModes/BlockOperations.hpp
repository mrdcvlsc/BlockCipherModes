#ifndef MRDCVLSC_BLOCK_OPERATIONS_HPP
#define MRDCVLSC_BLOCK_OPERATIONS_HPP

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <type_traits>

namespace Mode {
    namespace Operation {
        /// @brief performs an exclusive OR (XOR/EOR) operation.
        /// @tparam BLOCK_SIZE size of the block.
        /// @param dest starting pointer where the results will be stored.
        /// @param src XORed array to the dest array.
        template <size_t BLOCK_SIZE>
        void exor(unsigned char *dest, unsigned char *src) noexcept {
            for (size_t i = 0; i < BLOCK_SIZE; ++i) {
                dest[i] ^= src[i];
            }
        }

        /// @brief performs an exclusive OR (XOR/EOR) operation.
        /// @tparam BLOCK_SIZE size of the block.
        /// @tparam T cast limb type.
        /// @param dest starting pointer where the results will be stored.
        /// @param src XORed array to the dest array.
        template <size_t BLOCK_SIZE, class T>
        void exor(unsigned char *dest, unsigned char *src) noexcept {
            if constexpr (std::is_unsigned_v<T>) {
                constexpr size_t blockT = BLOCK_SIZE / sizeof(T);

                T *A = reinterpret_cast<T *>(dest);
                T *B = reinterpret_cast<T *>(src);

                for (size_t i = 0; i < blockT; i++) {
                    A[i] ^= B[i];
                }

                if constexpr (blockT * sizeof(T) < BLOCK_SIZE) {
                    for (size_t i = blockT * sizeof(T); i < BLOCK_SIZE; i++) {
                        dest[i] ^= src[i];
                    }
                }
            } else if constexpr (!std::is_unsigned_v<T>) {
                static_assert(std::is_unsigned_v<T>, "template arg 'T' should be unsigned integral type");
            }
        }
    } // namespace Operation
} // namespace Mode

#endif