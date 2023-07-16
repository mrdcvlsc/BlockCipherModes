# BlockCipherModes

![tests](https://github.com/mrdcvlsc/BlockCipherModes/actions/workflows/tests.yml/badge.svg)

A collection of different block cipher modes, designed to facilitate secure data encryption. This library focuses **exclusively** on providing implementations of block cipher modes and **does not include** block cipher algorithms or padding functions.

This library also aims to ease the integration of external or 3rd party block cipher functions or methods through the use of callback functions.

## **Block Cipher Mode vs Block Cipher**

A **block cipher mode** is a technique used in cryptography to encrypt/decrypt data using a **block cipher** algorithm.

**Block ciphers** operate on _fixed-size blocks_ of data and produce ciphertext as output. However, when encrypting large amounts of data, **block cipher modes** are needed to **handle multiple blocks** securely.

Some common **block cipher modes** include Electronic Codebook (ECB), Cipher Block Chaining (CBC), Counter (CTR), and Galois/Counter Mode (GCM).

These modes provide different approaches when encrypting and processing multiple blocks of data, ensuring confidentiality and integrity of the encrypted information.

## **Currently Supported Modes**

- :green_square: - already supported and available (done)
- :yellow_square: - will be supported in the future (pending)
- :red_square: - will not be supported

| Mode  | Name                  | Status               |
| ----- | --------------------- | :------------------: |
| `ECB` | Electronic Codebook   | :red_square:         |
| `CBC` | Cipher Block Chaining | :green_square:       |
| `OFB` | Output Feedback       | :yellow_square:      |
| `CFB` | Cipher Feedback       | :green_square:       |
| `CTR` | Counter               | :yellow_square:      |
| `GCM` | Galois/Counter Mode   | :yellow_square:      |

-----------

## **Minimum Requirement(s)**

- Requires C++17 so you need to compile it with the compilation flag `-std=c++17`.

## **Learn How To Use The Library**

1. **[Block Cipher Mode On A Single-Block](docs/sample1.md)**
2. **[Block Cipher Mode On Multi-Block](docs/sample2.md)**
3. **[Block Cipher Mode + Block Cipher : Local Access](docs/sample3.md)**
4. **[Block Cipher Mode + Block Cipher : Global Access](docs/sample4.md)**