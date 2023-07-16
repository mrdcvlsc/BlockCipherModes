## **1. Block Cipher Mode On A Single-Block**

Here is an example of the basic usage of the library.

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

  CBC<BLOCK_LEN>::encrypt(data, iv_enc, [](unsigned char* block) {
    // this is where you will encrypt the `block` and
    // sometime add padding.
    
    // But for this sample we just leave the block "as is", no
    // need to encrypt and decrypt, it will still work, but keep
    // in mind in real applications we should use a block cipher
    // inside this callback method to achieve maximum security.
  });

  CBC<BLOCK_LEN>::decrypt(data, iv_dec, [](unsigned char* block) {
    // this is where you will decrypt the `block`
    // but for this sample we just leave the block "as is"
  });
}
```

Both the `iv_enc`, `iv_dec` are modified
after every `encrypt`, `decrypt` function call,
the `data` array will also be **encrypted**, **decrypted**.

The IV arrays are modified based on the block cipher mode,
the modified IV is used for the next encryption or decryption
of the remaining blocks if dealing with multi-block data.

**Encrypted Value:**

```c++
// encrypted `data` array.
0xde, 0xac, 0xbc, 0xec, 0xce, 0xfb, 0xbc, 0xb9,
0x10, 0x69, 0x12, 0x30, 0x11, 0xee, 0xd8, 0x4d, 

// decrypted `data` array.
0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0xfa, 0x7e, 
```

**[View Next](sample2.md)**

----

### **Contents**

1. _[Go Back To README](../README.md)_
2. _[Block Cipher Mode On Multi-Block](sample2.md)_
3. _[Block Cipher Mode + Block Cipher : Local Access](sample3.md)_
4. _[Block Cipher Mode + Block Cipher : Global Access](sample4.md)_