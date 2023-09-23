#ifndef MRDCVLSC_CFB_HPP
#define MRDCVLSC_CFB_HPP

#include "BlockOperations.hpp"

namespace Mode {
    /// @brief CFB class.
    /// @tparam BLOCK_SIZE the size of a CFB block in bytes.
    template <size_t BLOCK_SIZE>
    struct CFB {
        /// @brief performs CFB mode block encryption.
        /// @param block byte array to be encrypt with CFB. (read+write)
        /// @param iv initial vector. (read+write)
        /// @param blockToEncrypt callback function that will encrypt the block using a choosen block cipher.
        template <typename function_t>
        static void encrypt(unsigned char *block, unsigned char *iv, function_t blockToEncrypt) noexcept {
            blockToEncrypt(iv);
            Operation::exor<BLOCK_SIZE, size_t>(block, iv);
            std::memcpy(iv, block, BLOCK_SIZE);
        }

        /// @brief performs CFB mode block decryption.
        /// @param block byte array to be decrypt with CFB. (read+write)
        /// @param iv initial vector. (read+write)
        /// @param blockToEncrypt callback function that will encrypt the block using a choosen block cipher).
        /// @warning In CFB mode we should USE again the SAME BLOCK CIPHER ENCRYPTION not its decryption.
        template <typename function_t>
        static void decrypt(unsigned char *block, unsigned char *iv, function_t blockToEncrypt) noexcept {
            unsigned char original_block[BLOCK_SIZE];
            std::memcpy(original_block, block, BLOCK_SIZE);

            blockToEncrypt(iv);
            Operation::exor<BLOCK_SIZE, size_t>(block, iv);
            std::memcpy(iv, original_block, BLOCK_SIZE);
        }
    };
} // namespace Mode

#endif