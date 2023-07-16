## **2. Block Cipher Mode On Multi-Block**

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
    CBC<BLOCK_LEN>::encrypt(&data[i * BLOCK_LEN], iv_enc, [](unsigned char* block) {
      // "as is" for this example.
    });
  }

  for (size_t i = 0; i < BLOCKS; i++) {
    CBC<BLOCK_LEN>::decrypt(&data[i * BLOCK_LEN], iv_dec, [](unsigned char* block) {
      // "as is" for this example.
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

**[View Next](sample3.md)**

----

### **Contents**

1. _[Go Back To README](../README.md)_
2. _[Block Cipher Mode On Multi-Block](sample2.md)_
3. _[Block Cipher Mode + Block Cipher : Local Access](sample3.md)_
4. _[Block Cipher Mode + Block Cipher : Global Access](sample4.md)_