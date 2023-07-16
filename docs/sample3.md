## **3. Block Cipher Mode + Block Cipher : Local Access**

_**Wrapping**_ the _**functions**_ in a _**class**_ is important
_**in order to access**_ the necessary _**methods**_ that we need
_**inside**_ the _**lambda function**_.

We can pass an **object instance** of the **class** in
the lambda capture scope to be able to use its methods.

If we also need a **variable** inside our lambda callback function
then we also need to pass those.

**Example:**

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

struct SudoCipher {
  void encrypt(unsigned char *block, size_t BLOCKSIZE) {
    for (size_t i = 0; i < BLOCKSIZE; ++i) {
      block[i] = ~block[i];
    }
  }

  void decrypt(unsigned char *block, size_t BLOCKSIZE) {
    for (size_t i = 0; i < BLOCKSIZE; ++i) {
      block[i] = ~block[i];
    }
  }
};

int main() {
  // object instance of the class.
  SudoCipher cipher;

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

  CBC<BLOCK_LEN>::encrypt(data, iv, [&cipher, BlockSize](unsigned char *block) {
    // non-constant expression variables like `BlockSize` are 
    // not accessible right away inside the lambda function so 
    // we need to pass it inside the lambda capture scope.
    cipher.encrypt(block, BlockSize);
  });

  std::cout << "Encrypted: "; display(data, BLOCK_LEN);

  CBC<BLOCK_LEN>::decrypt(data, iv_for_dec, [&cipher](unsigned char *block) {
    // constexpr variables like 'BLOCK_LEN` are already 
    // accessible inside the lambda function, so there is no 
    // need to pass it in the lambda capture scope.
    cipher.decrypt(block, BLOCK_LEN);
  });

  std::cout << "Decrypted: "; display(data, BLOCK_LEN);
}
```

compile with : ```clang++ -std=c++17 sample.cpp -o sample.out```

**[View Next](sample4.md)**

----

### **Contents**

1. _[Go Back To README](../README.md)_
2. _[Block Cipher Mode On Multi-Block](sample2.md)_
3. _[Block Cipher Mode + Block Cipher : Local Access](sample3.md)_
4. _[Block Cipher Mode + Block Cipher : Global Access](sample4.md)_