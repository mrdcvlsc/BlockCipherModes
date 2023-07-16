### **4. Block Cipher Mode + Block Cipher : Global Access**

Passing a global function or class with static methods are also possible.
With this method we **don't need to pass things** in the lambda capture scope.

```c++
// sample.cpp
#include <iostream>
#include <stdio.h>

#include "BlockCipherModes/cbc.hpp"

using namespace Mode;

void display(unsigned char *block, size_t length) {
  for (size_t i = 0; i < length; ++i) {
    printf("%02x " , block[i]);
  }
  std::cout << "\n\n";
}

template<size_t BLOCKSIZE>
struct SudoCipher {
  static void encrypt(unsigned char *block) {
    for (size_t i = 0; i < BLOCKSIZE; ++i) {
      block[i] = ~block[i];
    }
  }
};

void decrypt_global_fn(unsigned char *block) {
  for (size_t i = 0; i < 8; ++i) {
    block[i] = ~block[i];
  }
}

int main() {
  constexpr size_t BLOCK_LEN = 8;

  unsigned char data[BLOCK_LEN] = {
    0xde, 0xad, 0x2b, 0xad, 0xff, 0x11, 0x22, 0x33,
  };
  unsigned char iv[BLOCK_LEN] = {
    0xde, 0xed, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
  };
  unsigned char iv_for_dec[BLOCK_LEN] = {
    0xde, 0xed, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
  };

  size_t BlockSize = 8;

  std::cout << "Plain    : "; display(data, BLOCK_LEN);

  // no lambda capture arguments needed.
  CBC<BLOCK_LEN>::encrypt(data, iv, [](unsigned char *block) {
    SudoCipher<BLOCK_LEN>::encrypt(block);
  });

  std::cout << "Encrypted: "; display(data, BLOCK_LEN);

  CBC<BLOCK_LEN>::decrypt(data, iv_for_dec, [](unsigned char *block) {
    decrypt_global_fn(block);
  });

  std::cout << "Decrypted: "; display(data, BLOCK_LEN);
}
```

compile with : ```clang++ -std=c++17 sample.cpp -o sample.out```

**[View Start](sample1.md)**

----

### **Contents**

1. _[Go Back To README](../README.md)_
2. _[Block Cipher Mode On Multi-Block](sample2.md)_
3. _[Block Cipher Mode + Block Cipher : Local Access](sample3.md)_
4. _[Block Cipher Mode + Block Cipher : Global Access](sample4.md)_