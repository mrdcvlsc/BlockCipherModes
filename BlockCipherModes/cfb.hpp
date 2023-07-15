#ifndef MRDCVLSC_CFB_HPP
#define MRDCVLSC_CFB_HPP

#include "BlockOperations.hpp"
#include <iostream>

namespace Mode {
  /// @brief CFB class.
  /// @tparam BLOCK_SIZE the size of a CFB block in bytes.
  template <size_t BLOCK_SIZE>
  struct CFB {

    /// @brief performs CFB mode block encryption.
    /// @param iv initial vector - values will mutate after the function call.
    /// @param block CFB block to encrypt - values will mutate after the function call
    /// @param blockToEncrypt callback function that will encrypt the block.
    static void encrypt(
      unsigned char* iv,
      unsigned char* block,
      void (*blockToEncrypt)(unsigned char *)
    )
    {
      Operation::exor<BLOCK_SIZE, size_t>(block, iv);
      blockToEncrypt(block);
      std::memcpy(iv, block, BLOCK_SIZE);
    }

    /// @brief performs an exclusive OR (XOR/EOR) operation.
    /// @param iv initial vector.
    /// @param block block to encrypt.
    /// @param blockToEncrypt callback function that will encrypt the block.
    static void decrypt(
      unsigned char* iv,
      unsigned char* block,
      void (*blockToDecrypt)(unsigned char *)
    )
    {
      blockToDecrypt(block);
      Operation::exor<BLOCK_SIZE, size_t>(block, iv);
      std::memcpy(iv, block, BLOCK_SIZE);
    }
  };
} // namespace Mode

#endif