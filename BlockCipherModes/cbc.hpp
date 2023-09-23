#ifndef MRDCVLSC_CBC_HPP
#define MRDCVLSC_CBC_HPP

#include "BlockOperations.hpp"

namespace Mode {
    /// @brief CBC class.
    /// @tparam BLOCK_SIZE the size of a CBC block in bytes.
    template <size_t BLOCK_SIZE>
    struct CBC {
        /// @brief performs CBC mode block encryption.
        /// @param block byte array to be encrypt with CBC. (read+write)
        /// @param iv initial vector. (read+write)
        /// @param blockToEncrypt callback function that will encrypt the block using a choosen block cipher.
        template <typename function_t>
        static void encrypt(unsigned char *block, unsigned char *iv, function_t blockToEncrypt) noexcept {
            Operation::exor<BLOCK_SIZE, size_t>(block, iv);
            blockToEncrypt(block);
            std::memcpy(iv, block, BLOCK_SIZE);
        }

        /// @brief performs CBC mode block decryption.
        /// @param block byte array to be decrypt with CBC. (read+write)
        /// @param iv initial vector. (read+write)
        /// @param blockToEncrypt callback function that will decrypt the block using a choosen block cipher.
        template <typename function_t>
        static void decrypt(unsigned char *block, unsigned char *iv, function_t blockToDecrypt) noexcept {
            unsigned char original_block[BLOCK_SIZE];
            std::memcpy(original_block, block, BLOCK_SIZE);

            blockToDecrypt(block);
            Operation::exor<BLOCK_SIZE, size_t>(block, iv);
            std::memcpy(iv, original_block, BLOCK_SIZE);
        }
    };
} // namespace Mode

#endif