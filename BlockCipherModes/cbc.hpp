#ifndef MRDCVLSC_CBC_HPP
#define MRDCVLSC_CBC_HPP

#include "BlockOperations.hpp"
#include <iostream>

namespace Mode {
  /// @brief CBC class.
  /// @tparam BLOCK_SIZE the size of a CBC block in bytes.
  template <size_t BLOCK_SIZE>
  struct CBC {

    /// @brief performs CBC mode block encryption.
    /// @param iv initial vector - values will mutate after the function call.
    /// @param block CBC block to encrypt - values will mutate after the function call
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
      unsigned char original_block[BLOCK_SIZE];
      std::memcpy(original_block, block, BLOCK_SIZE);
      blockToDecrypt(block);
      Operation::exor<BLOCK_SIZE, size_t>(block, iv);
      // Operation::exor<BLOCK_SIZE, size_t>(iv, block);
      std::memcpy(iv, original_block, BLOCK_SIZE);
    }
  };
} // namespace Mode

#endif