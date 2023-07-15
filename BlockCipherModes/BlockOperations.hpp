#ifndef MRDCVLSC_BLOCK_OPERATIONS_HPP
#define MRDCVLSC_BLOCK_OPERATIONS_HPP

#include <iostream>

namespace Mode {
  namespace Operation {

    /// @brief performs an exclusive OR (XOR/EOR) operation.
    /// @tparam BLOCK_SIZE size of the block.
    /// @param dest starting pointer where the results will be stored.
    /// @param src XORed array to the dest array.
    template <size_t BLOCK_SIZE>
    void exor(unsigned char *dest, unsigned char *src) {
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
    void exor(unsigned char *dest, unsigned char *src) {
      if constexpr (std::is_unsigned_v<T>) {
        constexpr size_t blockT = BLOCK_SIZE / sizeof(T);

        T *A = (T *) dest;
        T *B = (T *) src;

        for (size_t i = 0; i < blockT; i++) {
          A[i] ^= B[i];
        }

        for (size_t i = blockT * sizeof(T); i < BLOCK_SIZE; i++) {
          dest[i] ^= src[i];
        }
      } else if constexpr (!std::is_unsigned_v<T>) {
        throw "exor template argument type is not an integral type";
      }
    }
  } // namespace Block
} // namespace Mode

#endif