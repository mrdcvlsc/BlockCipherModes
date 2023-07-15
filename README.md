# BlockCipherModes

![tests](https://github.com/mrdcvlsc/BlockCipherModes/actions/workflows/tests.yml/badge.svg)

A collection of different block cipher modes, designed to facilitate secure data encryption. This library focuses **exclusively** on providing implementations of block cipher modes and **does not include** block cipher algorithms or padding functions.

This library also aims to ease the integration of external or 3rd party block cipher functions or methods through the use of callback functions.

## **Block Cipher Mode vs Block Cipher**

A **block cipher mode** is a technique used in cryptography to encrypt/decrypt data using a **block cipher** algorithm.

**Block ciphers** operate on _fixed-size blocks_ of data and produce ciphertext as output. However, when encrypting large amounts of data, **block cipher modes** are needed to **handle multiple blocks** securely.

Some common **block cipher modes** include Electronic Codebook (ECB), Cipher Block Chaining (CBC), Counter (CTR), and Galois/Counter Mode (GCM).

These modes provide different approaches when encrypting and processing multiple blocks of data, ensuring confidentiality and integrity of the encrypted information.

-----------

## **Requirements**

- Requires C++17 so you need to compile it with the compilation flag `-std=c++17`.

## **Sample program 1:**

```c++
/*    sample.cpp    */
#include <iostream>
#include "BlockCipherModes/cbc.hpp"

using namespace Mode;

int main()
{
  constexpr size_t BLOCK_LEN = 16;

  unsigned char iv_enc[BLOCK_LEN] = {
    0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
    0xba, 0xd2, 0xde, 0xed, 0xff, 0x11, 0x22, 0x33,
  };

  unsigned char iv_dec[BLOCK_LEN] = {
    0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
    0xba, 0xd2, 0xde, 0xed, 0xff, 0x11, 0x22, 0x33,
  };

  unsigned char data[BLOCK_LEN] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0xfa, 0x7e, 
  };

  CBC<BLOCK_LEN>::encrypt(iv_enc, data, [](unsigned char* block) {
    // this is where you will encrypt the `block`
    
    // But for this sample we just leave the block "as is", no
    // need to encrypt and decrypt, it will still work, but keep
    // in mind in real applications we should use a block cipher
    // inside this callback method to achieve maximum security.
  });

  CBC<BLOCK_LEN>::decrypt(iv_dec, data, [](unsigned char* block) {
    // this is where you will decrypt the `block`
    // but for this sample we just leave the block as is
  });
}
```

Both the `iv_enc`, `iv_dec` are modified
after every `encrypt`, `decrypt` function call,
the `data` array will also be **encrypted**, **decrypted**.

The IV arrays are modified based on the block cipher mode,
the modified IV is used for the next encryption or decryption
of the remaining blocks if dealing with multi-block data :
[see sample program 2](#sample-program-2).

**Encrypted Value:**

```c++
// encrypted `data` array.
0xde, 0xac, 0xbc, 0xec, 0xce, 0xfb, 0xbc, 0xb9,
0x10, 0x69, 0x12, 0x30, 0x11, 0xee, 0xd8, 0x4d, 

// decrypted `data` array.
0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0xfa, 0x7e, 
```

## **Sample program 2:**

```c++
/*    sample.cpp    */
#include <iostream>
#include "BlockCipherModes/cbc.hpp"

using namespace Mode;

int main()
{
  constexpr size_t DATA_SIZE = 16;
  constexpr size_t BLOCK_LEN = 8;
  constexpr size_t BLOCKS = DATA_SIZE / BLOCK_LEN;

  unsigned char iv_enc[BLOCK_LEN] = {
    0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
  };

  unsigned char iv_dec[BLOCK_LEN] = {
    0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
  };

  unsigned char data[DATA_SIZE] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0xfa, 0x7e,
  };

  unsigned char sbackup[DATA_SIZE] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0xfa, 0x7e,
  };

  unsigned char validator[DATA_SIZE] = {};

  unsigned char manual_iv[BLOCK_LEN];
  std::memcpy(manual_iv, iv_enc, BLOCK_LEN);
  
  for (size_t i = 0; i < BLOCKS; ++i) {
    for (size_t j = 0; j < BLOCK_LEN; ++j) {
      validator[(i * BLOCK_LEN) + j] =  manual_iv[j] ^ data[(i * BLOCK_LEN) + j];
      manual_iv[j] = validator[(i * BLOCK_LEN) + j];
    }
  }

  // ============= MULTI-BLOCK DATA USAGE =============
  for (size_t i = 0; i < BLOCKS; i++) {
    CBC<BLOCK_LEN>::encrypt(iv_enc, &data[i * BLOCK_LEN], [](unsigned char* block) {
      // as is for this example.
    });
  }

  t.byte_eq(data, validator, sizeof(validator), "CBC Mode 2 Block 8 Encrypt");

  for (size_t i = 0; i < BLOCKS; i++) {
    CBC<BLOCK_LEN>::decrypt(iv_dec, &data[i * BLOCK_LEN], [](unsigned char* block) {
      // as is for this example.
    });
  }
}
```

**Encrypted Value:**

```c++
// encrypted `data` array.
0xde, 0xac, 0xdc, 0xaf, 0xd8, 0xaa, 0xde, 0xad,
0x74, 0x16, 0xb8, 0xcb, 0x56, 0x34, 0xac, 0x4a, 

// decrypted `data` array.
0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0xfa, 0x7e, 
```