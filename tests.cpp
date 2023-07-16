#include <iostream>
#include <vector>

#include "BlockCipherModes/cbc.hpp"
#include "BlockCipherModes/cfb.hpp"
#include "small_test.hpp"

template <size_t BLOCKSIZE>
struct SudoCipher {
  void encrypt(unsigned char *) {
    // encrypt block here.
  }

  void decrypt(unsigned char *) {
    // decrypt block here.
  }
};

int main() {
  smlts::test t;

  // ############# CBC ###############

  std::cout << "CBC Mode Test Block 16 : \n";
  {
    constexpr size_t BLOCK_SIZE = 16;
    SudoCipher<BLOCK_SIZE> cipher;

    unsigned char iv_original[BLOCK_SIZE] = {
      0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0xba, 0xd2, 0xde, 0xed, 0xff, 0x11, 0x22, 0x33,
    };

    unsigned char iv[BLOCK_SIZE] = {
      0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0xba, 0xd2, 0xde, 0xed, 0xff, 0x11, 0x22, 0x33,
    };

    unsigned char iv_bkcup[BLOCK_SIZE] = {
      0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0xba, 0xd2, 0xde, 0xed, 0xff, 0x11, 0x22, 0x33,
    };

    unsigned char subject[BLOCK_SIZE] = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0xfa, 0x7e,
    };

    unsigned char sbackup[BLOCK_SIZE] = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0xfa, 0x7e,
    };

    unsigned char validator[BLOCK_SIZE] = {};

    for (size_t i = 0; i < BLOCK_SIZE; ++i) {
      validator[i] = iv[i] ^ subject[i];
    }

    Mode::CBC<BLOCK_SIZE>::encrypt(subject, iv, [&cipher](unsigned char *block) { cipher.encrypt(block); });

    t.byte_eq(subject, validator, sizeof(validator), "CBC Mode Block 16 Encrypt");

    Mode::CBC<BLOCK_SIZE>::decrypt(subject, iv_bkcup, [&cipher](unsigned char *block) { cipher.decrypt(block); });

    t.byte_eq(subject, sbackup, sizeof(sbackup), "CBC Mode Block 16 Decrypt");
    t.byte_eq(iv, iv_bkcup, sizeof(iv_bkcup), "CBC Mode IV Block 16");
    t.byte_neq(iv_original, iv, sizeof(iv_original), "CBC Mode Block 16 Altered");
  }

  std::cout << "CBC Mode Test Block 8 : \n";
  {
    constexpr size_t BLOCK_SIZE = 8;
    SudoCipher<BLOCK_SIZE> cipher;

    unsigned char iv_original[BLOCK_SIZE] = {
      0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
    };

    unsigned char iv[BLOCK_SIZE] = {
      0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
    };

    unsigned char iv_bkcup[BLOCK_SIZE] = {
      0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
    };

    unsigned char subject[BLOCK_SIZE] = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    };

    unsigned char sbackup[BLOCK_SIZE] = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    };

    unsigned char validator[BLOCK_SIZE] = {};

    for (size_t i = 0; i < BLOCK_SIZE; ++i) {
      validator[i] = iv[i] ^ subject[i];
    }

    Mode::CBC<BLOCK_SIZE>::encrypt(subject, iv, [&cipher](unsigned char *block) { cipher.encrypt(block); });

    t.byte_eq(subject, validator, sizeof(validator), "CBC Mode Block 8 Encrypt");

    Mode::CBC<BLOCK_SIZE>::decrypt(subject, iv_bkcup, [&cipher](unsigned char *block) { cipher.decrypt(block); });

    t.byte_eq(subject, sbackup, sizeof(sbackup), "CBC Mode Block 8 Decrypt");
    t.byte_eq(iv, iv_bkcup, sizeof(iv_bkcup), "CBC Mode IV Block 8");
    t.byte_neq(iv_original, iv, sizeof(iv_original), "CBC Mode Block 8 Altered");
  }

  std::cout << "CBC Mode Test Block 4 : \n";
  {
    constexpr size_t BLOCK_SIZE = 4;
    SudoCipher<BLOCK_SIZE> cipher;

    unsigned char iv_original[BLOCK_SIZE] = {0xde, 0xad, 0xbe, 0xef};

    unsigned char iv[BLOCK_SIZE] = {0xde, 0xad, 0xbe, 0xef};

    unsigned char iv_bkcup[BLOCK_SIZE] = {0xde, 0xad, 0xbe, 0xef};

    unsigned char subject[BLOCK_SIZE] = {0x00, 0x01, 0x02, 0x03};

    unsigned char sbackup[BLOCK_SIZE] = {0x00, 0x01, 0x02, 0x03};

    unsigned char validator[BLOCK_SIZE] = {};

    for (size_t i = 0; i < BLOCK_SIZE; ++i) {
      validator[i] = iv[i] ^ subject[i];
    }

    Mode::CBC<BLOCK_SIZE>::encrypt(subject, iv, [&cipher](unsigned char *block) { cipher.encrypt(block); });

    t.byte_eq(subject, validator, sizeof(validator), "CBC Mode Block 4 Encrypt");

    Mode::CBC<BLOCK_SIZE>::decrypt(subject, iv_bkcup, [&cipher](unsigned char *block) { cipher.decrypt(block); });

    t.byte_eq(subject, sbackup, sizeof(sbackup), "CBC Mode Block 4 Decrypt");
    t.byte_eq(iv, iv_bkcup, sizeof(iv_bkcup), "CBC Mode IV Block 4");
    t.byte_neq(iv_original, iv, sizeof(iv_original), "CBC Mode Block 4 Altered");
  }

  std::cout << "CBC Mode Test Block 3 : \n";
  {

    constexpr size_t BLOCK_SIZE = 3;
    SudoCipher<BLOCK_SIZE> cipher;

    unsigned char iv_original[BLOCK_SIZE] = {0xde, 0xad, 0xbe};

    unsigned char iv[BLOCK_SIZE] = {0xde, 0xad, 0xbe};

    unsigned char iv_bkcup[BLOCK_SIZE] = {0xde, 0xad, 0xbe};

    unsigned char subject[BLOCK_SIZE] = {0x00, 0x01, 0x02};

    unsigned char sbackup[BLOCK_SIZE] = {0x00, 0x01, 0x02};

    unsigned char validator[BLOCK_SIZE] = {};

    for (size_t i = 0; i < BLOCK_SIZE; ++i) {
      validator[i] = iv[i] ^ subject[i];
    }

    Mode::CBC<BLOCK_SIZE>::encrypt(subject, iv, [&cipher](unsigned char *block) { cipher.encrypt(block); });

    t.byte_eq(subject, validator, sizeof(validator), "CBC Mode Block 3 Encrypt");

    Mode::CBC<BLOCK_SIZE>::decrypt(subject, iv_bkcup, [&cipher](unsigned char *block) { cipher.decrypt(block); });

    t.byte_eq(subject, sbackup, sizeof(sbackup), "CBC Mode Block 3 Decrypt");
    t.byte_eq(iv, iv_bkcup, sizeof(iv_bkcup), "CBC Mode IV Block 3");
    t.byte_neq(iv_original, iv, sizeof(iv_original), "CBC Mode Block 3 Altered");
  }

  std::cout << "CBC Mode Test Block 10 : \n";
  {

    constexpr size_t BLOCK_SIZE = 10;
    SudoCipher<BLOCK_SIZE> cipher;

    unsigned char iv_original[BLOCK_SIZE] = {
      0xde, 0xad, 0xbe, 0xef, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01,
    };

    unsigned char iv[BLOCK_SIZE] = {
      0xde, 0xad, 0xbe, 0xef, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01,
    };

    unsigned char iv_bkcup[BLOCK_SIZE] = {
      0xde, 0xad, 0xbe, 0xef, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01,
    };

    unsigned char subject[BLOCK_SIZE] = {
      0x00, 0x01, 0x02, 0x03, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
    };

    unsigned char sbackup[BLOCK_SIZE] = {
      0x00, 0x01, 0x02, 0x03, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
    };

    unsigned char validator[BLOCK_SIZE] = {};

    for (size_t i = 0; i < BLOCK_SIZE; ++i) {
      validator[i] = iv[i] ^ subject[i];
    }

    Mode::CBC<BLOCK_SIZE>::encrypt(subject, iv, [&cipher](unsigned char *block) { cipher.encrypt(block); });

    t.byte_eq(subject, validator, sizeof(validator), "CBC Mode Block 10 Encrypt");

    Mode::CBC<BLOCK_SIZE>::decrypt(subject, iv_bkcup, [&cipher](unsigned char *block) { cipher.decrypt(block); });

    t.byte_eq(subject, sbackup, sizeof(sbackup), "CBC Mode Block 10 Decrypt");
    t.byte_eq(iv, iv_bkcup, sizeof(iv_bkcup), "CBC Mode IV Block 10");
    t.byte_neq(iv_original, iv, sizeof(iv_original), "CBC Mode Block 10 Altered");
  }

  std::cout << "CBC Mode Test Block 15 : \n";
  {

    constexpr size_t BLOCK_SIZE = 15;
    SudoCipher<BLOCK_SIZE> cipher;

    unsigned char iv_original[BLOCK_SIZE] = {
      0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0xba, 0xd2, 0xde, 0xed, 0xff, 0x11, 0x22,
    };

    unsigned char iv[BLOCK_SIZE] = {
      0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0xba, 0xd2, 0xde, 0xed, 0xff, 0x11, 0x22,
    };

    unsigned char iv_bkcup[BLOCK_SIZE] = {
      0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0xba, 0xd2, 0xde, 0xed, 0xff, 0x11, 0x22,
    };

    unsigned char subject[BLOCK_SIZE] = {
      0x00, 0x01, 0x02, 0x03, 0xff, 0xff, 0xff, 0xff, 0xff, 0x22, 0x22, 0x22, 0x22, 0x22, 0xdd,
    };

    unsigned char sbackup[BLOCK_SIZE] = {
      0x00, 0x01, 0x02, 0x03, 0xff, 0xff, 0xff, 0xff, 0xff, 0x22, 0x22, 0x22, 0x22, 0x22, 0xdd,
    };

    unsigned char validator[BLOCK_SIZE] = {};

    for (size_t i = 0; i < BLOCK_SIZE; ++i) {
      validator[i] = iv[i] ^ subject[i];
    }

    Mode::CBC<BLOCK_SIZE>::encrypt(subject, iv, [&cipher](unsigned char *block) { cipher.encrypt(block); });

    t.byte_eq(subject, validator, sizeof(validator), "CBC Mode Block 15 Encrypt");

    Mode::CBC<BLOCK_SIZE>::decrypt(subject, iv_bkcup, [&cipher](unsigned char *block) { cipher.decrypt(block); });

    t.byte_eq(subject, sbackup, sizeof(sbackup), "CBC Mode Block 15 Decrypt");
    t.byte_eq(iv, iv_bkcup, sizeof(iv_bkcup), "CBC Mode IV Block 15");
    t.byte_neq(iv_original, iv, sizeof(iv_original), "CBC Mode Block 15 Altered");
  }

  std::cout << "CBC Mode Test Block 17 : \n";
  {

    constexpr size_t BLOCK_SIZE = 17;
    SudoCipher<BLOCK_SIZE> cipher;

    unsigned char iv_original[BLOCK_SIZE] = {
      0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0xba, 0xd2, 0xde, 0xed, 0xff, 0x11, 0x22, 0xcc, 0xf1,
    };

    unsigned char iv[BLOCK_SIZE] = {
      0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0xba, 0xd2, 0xde, 0xed, 0xff, 0x11, 0x22, 0xcc, 0xf1,
    };

    unsigned char iv_bkcup[BLOCK_SIZE] = {
      0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0xba, 0xd2, 0xde, 0xed, 0xff, 0x11, 0x22, 0xcc, 0xf1,
    };

    unsigned char subject[BLOCK_SIZE] = {
      0x00, 0x01, 0x02, 0x03, 0xff, 0xff, 0xff, 0xff, 0xff, 0x22, 0x22, 0x22, 0x22, 0x22, 0xdd, 0xfa, 0x0b,
    };

    unsigned char sbackup[BLOCK_SIZE] = {
      0x00, 0x01, 0x02, 0x03, 0xff, 0xff, 0xff, 0xff, 0xff, 0x22, 0x22, 0x22, 0x22, 0x22, 0xdd, 0xfa, 0x0b,
    };

    unsigned char validator[BLOCK_SIZE] = {};

    for (size_t i = 0; i < BLOCK_SIZE; ++i) {
      validator[i] = iv[i] ^ subject[i];
    }

    Mode::CBC<BLOCK_SIZE>::encrypt(subject, iv, [&cipher](unsigned char *block) { cipher.encrypt(block); });

    t.byte_eq(subject, validator, sizeof(validator), "CBC Mode Block 17 Encrypt");

    Mode::CBC<BLOCK_SIZE>::decrypt(subject, iv_bkcup, [&cipher](unsigned char *block) { cipher.decrypt(block); });

    t.byte_eq(subject, sbackup, sizeof(sbackup), "CBC Mode Block 17 Decrypt");
    t.byte_eq(iv, iv_bkcup, sizeof(iv_bkcup), "CBC Mode IV Block 17");
    t.byte_neq(iv_original, iv, sizeof(iv_original), "CBC Mode Block 17 Altered");
  }

  std::cout << "CBC Mode Test two 8 Block : \n";
  {
    constexpr size_t DATA_SIZE = 16;
    constexpr size_t BLOCK_SIZE = 8;
    SudoCipher<BLOCK_SIZE> cipher;

    constexpr size_t BLOCKS = DATA_SIZE / BLOCK_SIZE;

    unsigned char iv_original[BLOCK_SIZE] = {
      0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
    };

    unsigned char iv[BLOCK_SIZE] = {
      0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
    };

    unsigned char iv_bkcup[BLOCK_SIZE] = {
      0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
    };

    unsigned char subject[DATA_SIZE] = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0xfa, 0x7e,
    };

    unsigned char sbackup[DATA_SIZE] = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0xfa, 0x7e,
    };

    unsigned char validator[DATA_SIZE] = {};

    unsigned char iv_block[BLOCK_SIZE];
    std::memcpy(iv_block, iv, BLOCK_SIZE);

    for (size_t i = 0; i < BLOCKS; ++i) {
      for (size_t j = 0; j < BLOCK_SIZE; ++j) {
        validator[(i * BLOCK_SIZE) + j] = iv_block[j] ^ subject[(i * BLOCK_SIZE) + j];
        iv_block[j] = validator[(i * BLOCK_SIZE) + j];
      }
    }

    for (size_t i = 0; i < BLOCKS; i++) {
      Mode::CBC<BLOCK_SIZE>::encrypt(&subject[i * BLOCK_SIZE], iv, [&cipher](unsigned char *block) {
        cipher.encrypt(block);
      });
    }

    t.byte_eq(subject, validator, sizeof(validator), "CBC Mode 2 Block 8 Encrypt");

    for (size_t i = 0; i < BLOCKS; i++) {
      Mode::CBC<BLOCK_SIZE>::decrypt(&subject[i * BLOCK_SIZE], iv_bkcup, [&cipher](unsigned char *block) {
        cipher.decrypt(block);
      });
    }

    t.byte_eq(subject, sbackup, sizeof(sbackup), "CBC Mode 2 Block 8 Decrypt");
    t.byte_eq(iv, iv_bkcup, sizeof(iv_bkcup), "CBC Mode IV 2 Block 8");
    t.byte_neq(iv_original, iv, sizeof(iv_original), "CBC Mode 2 Block 8 Altered");
  }

  std::cout << "CBC Mode Test eight 2 Block : \n";
  {
    constexpr size_t DATA_SIZE = 16;
    constexpr size_t BLOCK_SIZE = 2;
    SudoCipher<BLOCK_SIZE> cipher;

    constexpr size_t BLOCKS = DATA_SIZE / BLOCK_SIZE;

    unsigned char iv_original[BLOCK_SIZE] = {
      0xde,
      0xad,
    };

    unsigned char iv[BLOCK_SIZE] = {
      0xde,
      0xad,
    };

    unsigned char iv_bkcup[BLOCK_SIZE] = {
      0xde,
      0xad,
    };

    unsigned char subject[DATA_SIZE] = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0xfa, 0x7e,
    };

    unsigned char sbackup[DATA_SIZE] = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0xfa, 0x7e,
    };

    unsigned char validator[DATA_SIZE] = {};

    unsigned char iv_block[BLOCK_SIZE];
    std::memcpy(iv_block, iv, BLOCK_SIZE);

    for (size_t i = 0; i < BLOCKS; ++i) {
      for (size_t j = 0; j < BLOCK_SIZE; ++j) {
        validator[(i * BLOCK_SIZE) + j] = iv_block[j] ^ subject[(i * BLOCK_SIZE) + j];
        iv_block[j] = validator[(i * BLOCK_SIZE) + j];
      }
    }

    for (size_t i = 0; i < BLOCKS; i++) {
      Mode::CBC<BLOCK_SIZE>::encrypt(&subject[i * BLOCK_SIZE], iv, [&cipher](unsigned char *block) {
        cipher.encrypt(block);
      });
    }

    t.byte_eq(subject, validator, sizeof(validator), "CBC Mode eight block of size 8 Encrypt");

    for (size_t i = 0; i < BLOCKS; i++) {
      Mode::CBC<BLOCK_SIZE>::decrypt(&subject[i * BLOCK_SIZE], iv_bkcup, [&cipher](unsigned char *block) {
        cipher.decrypt(block);
      });
    }

    t.byte_eq(subject, sbackup, sizeof(sbackup), "CBC Mode eight block of size 8 Decrypt");
    t.byte_eq(iv, iv_bkcup, sizeof(iv_bkcup), "CBC Mode IV eight block of size 8");
    t.byte_neq(iv_original, iv, sizeof(iv_original), "CBC Mode eight block of size 8 Altered");
  }

  //

  // ############# CFB ###############

  std::cout << "CFB Mode Test Block 16 : \n";
  {
    constexpr size_t BLOCK_SIZE = 16;
    SudoCipher<BLOCK_SIZE> cipher;

    unsigned char iv_original[BLOCK_SIZE] = {
      0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0xba, 0xd2, 0xde, 0xed, 0xff, 0x11, 0x22, 0x33,
    };

    unsigned char iv[BLOCK_SIZE] = {
      0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0xba, 0xd2, 0xde, 0xed, 0xff, 0x11, 0x22, 0x33,
    };

    unsigned char iv_bkcup[BLOCK_SIZE] = {
      0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0xba, 0xd2, 0xde, 0xed, 0xff, 0x11, 0x22, 0x33,
    };

    unsigned char subject[BLOCK_SIZE] = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0xfa, 0x7e,
    };

    unsigned char sbackup[BLOCK_SIZE] = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0xfa, 0x7e,
    };

    unsigned char validator[BLOCK_SIZE] = {};

    for (size_t i = 0; i < BLOCK_SIZE; ++i) {
      validator[i] = iv[i] ^ subject[i];
    }

    Mode::CFB<BLOCK_SIZE>::encrypt(subject, iv, [&cipher](unsigned char *block) { cipher.encrypt(block); });

    t.byte_eq(subject, validator, sizeof(validator), "CFB Mode Block 16 Encrypt");

    Mode::CFB<BLOCK_SIZE>::decrypt(subject, iv_bkcup, [&cipher](unsigned char *block) { cipher.decrypt(block); });

    t.byte_eq(subject, sbackup, sizeof(sbackup), "CFB Mode Block 16 Decrypt");
    t.byte_eq(iv, iv_bkcup, sizeof(iv_bkcup), "CFB Mode IV Block 16");
    t.byte_neq(iv_original, iv, sizeof(iv_original), "CFB Mode Block 16 Altered");
  }

  std::cout << "CFB Mode Test Block 8 : \n";
  {
    constexpr size_t BLOCK_SIZE = 8;
    SudoCipher<BLOCK_SIZE> cipher;

    unsigned char iv_original[BLOCK_SIZE] = {
      0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
    };

    unsigned char iv[BLOCK_SIZE] = {
      0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
    };

    unsigned char iv_bkcup[BLOCK_SIZE] = {
      0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
    };

    unsigned char subject[BLOCK_SIZE] = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    };

    unsigned char sbackup[BLOCK_SIZE] = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    };

    unsigned char validator[BLOCK_SIZE] = {};

    for (size_t i = 0; i < BLOCK_SIZE; ++i) {
      validator[i] = iv[i] ^ subject[i];
    }

    Mode::CFB<BLOCK_SIZE>::encrypt(subject, iv, [&cipher](unsigned char *block) { cipher.encrypt(block); });

    t.byte_eq(subject, validator, sizeof(validator), "CFB Mode Block 8 Encrypt");

    Mode::CFB<BLOCK_SIZE>::decrypt(subject, iv_bkcup, [&cipher](unsigned char *block) { cipher.decrypt(block); });

    t.byte_eq(subject, sbackup, sizeof(sbackup), "CFB Mode Block 8 Decrypt");
    t.byte_eq(iv, iv_bkcup, sizeof(iv_bkcup), "CFB Mode IV Block 8");
    t.byte_neq(iv_original, iv, sizeof(iv_original), "CFB Mode Block 8 Altered");
  }

  std::cout << "CFB Mode Test Block 4 : \n";
  {
    constexpr size_t BLOCK_SIZE = 4;
    SudoCipher<BLOCK_SIZE> cipher;

    unsigned char iv_original[BLOCK_SIZE] = {0xde, 0xad, 0xbe, 0xef};

    unsigned char iv[BLOCK_SIZE] = {0xde, 0xad, 0xbe, 0xef};

    unsigned char iv_bkcup[BLOCK_SIZE] = {0xde, 0xad, 0xbe, 0xef};

    unsigned char subject[BLOCK_SIZE] = {0x00, 0x01, 0x02, 0x03};

    unsigned char sbackup[BLOCK_SIZE] = {0x00, 0x01, 0x02, 0x03};

    unsigned char validator[BLOCK_SIZE] = {};

    for (size_t i = 0; i < BLOCK_SIZE; ++i) {
      validator[i] = iv[i] ^ subject[i];
    }

    Mode::CFB<BLOCK_SIZE>::encrypt(subject, iv, [&cipher](unsigned char *block) { cipher.encrypt(block); });

    t.byte_eq(subject, validator, sizeof(validator), "CFB Mode Block 4 Encrypt");

    Mode::CFB<BLOCK_SIZE>::decrypt(subject, iv_bkcup, [&cipher](unsigned char *block) { cipher.decrypt(block); });

    t.byte_eq(subject, sbackup, sizeof(sbackup), "CFB Mode Block 4 Decrypt");
    t.byte_eq(iv, iv_bkcup, sizeof(iv_bkcup), "CFB Mode IV Block 4");
    t.byte_neq(iv_original, iv, sizeof(iv_original), "CFB Mode Block 4 Altered");
  }

  std::cout << "CFB Mode Test Block 3 : \n";
  {

    constexpr size_t BLOCK_SIZE = 3;
    SudoCipher<BLOCK_SIZE> cipher;

    unsigned char iv_original[BLOCK_SIZE] = {0xde, 0xad, 0xbe};

    unsigned char iv[BLOCK_SIZE] = {0xde, 0xad, 0xbe};

    unsigned char iv_bkcup[BLOCK_SIZE] = {0xde, 0xad, 0xbe};

    unsigned char subject[BLOCK_SIZE] = {0x00, 0x01, 0x02};

    unsigned char sbackup[BLOCK_SIZE] = {0x00, 0x01, 0x02};

    unsigned char validator[BLOCK_SIZE] = {};

    for (size_t i = 0; i < BLOCK_SIZE; ++i) {
      validator[i] = iv[i] ^ subject[i];
    }

    Mode::CFB<BLOCK_SIZE>::encrypt(subject, iv, [&cipher](unsigned char *block) { cipher.encrypt(block); });

    t.byte_eq(subject, validator, sizeof(validator), "CFB Mode Block 3 Encrypt");

    Mode::CFB<BLOCK_SIZE>::decrypt(subject, iv_bkcup, [&cipher](unsigned char *block) { cipher.decrypt(block); });

    t.byte_eq(subject, sbackup, sizeof(sbackup), "CFB Mode Block 3 Decrypt");
    t.byte_eq(iv, iv_bkcup, sizeof(iv_bkcup), "CFB Mode IV Block 3");
    t.byte_neq(iv_original, iv, sizeof(iv_original), "CFB Mode Block 3 Altered");
  }

  std::cout << "CFB Mode Test Block 10 : \n";
  {

    constexpr size_t BLOCK_SIZE = 10;
    SudoCipher<BLOCK_SIZE> cipher;

    unsigned char iv_original[BLOCK_SIZE] = {
      0xde, 0xad, 0xbe, 0xef, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01,
    };

    unsigned char iv[BLOCK_SIZE] = {
      0xde, 0xad, 0xbe, 0xef, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01,
    };

    unsigned char iv_bkcup[BLOCK_SIZE] = {
      0xde, 0xad, 0xbe, 0xef, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01,
    };

    unsigned char subject[BLOCK_SIZE] = {
      0x00, 0x01, 0x02, 0x03, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
    };

    unsigned char sbackup[BLOCK_SIZE] = {
      0x00, 0x01, 0x02, 0x03, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
    };

    unsigned char validator[BLOCK_SIZE] = {};

    for (size_t i = 0; i < BLOCK_SIZE; ++i) {
      validator[i] = iv[i] ^ subject[i];
    }

    Mode::CFB<BLOCK_SIZE>::encrypt(subject, iv, [&cipher](unsigned char *block) { cipher.encrypt(block); });

    t.byte_eq(subject, validator, sizeof(validator), "CFB Mode Block 10 Encrypt");

    Mode::CFB<BLOCK_SIZE>::decrypt(subject, iv_bkcup, [&cipher](unsigned char *block) { cipher.decrypt(block); });

    t.byte_eq(subject, sbackup, sizeof(sbackup), "CFB Mode Block 10 Decrypt");
    t.byte_eq(iv, iv_bkcup, sizeof(iv_bkcup), "CFB Mode IV Block 10");
    t.byte_neq(iv_original, iv, sizeof(iv_original), "CFB Mode Block 10 Altered");
  }

  std::cout << "CFB Mode Test Block 15 : \n";
  {

    constexpr size_t BLOCK_SIZE = 15;
    SudoCipher<BLOCK_SIZE> cipher;

    unsigned char iv_original[BLOCK_SIZE] = {
      0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0xba, 0xd2, 0xde, 0xed, 0xff, 0x11, 0x22,
    };

    unsigned char iv[BLOCK_SIZE] = {
      0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0xba, 0xd2, 0xde, 0xed, 0xff, 0x11, 0x22,
    };

    unsigned char iv_bkcup[BLOCK_SIZE] = {
      0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0xba, 0xd2, 0xde, 0xed, 0xff, 0x11, 0x22,
    };

    unsigned char subject[BLOCK_SIZE] = {
      0x00, 0x01, 0x02, 0x03, 0xff, 0xff, 0xff, 0xff, 0xff, 0x22, 0x22, 0x22, 0x22, 0x22, 0xdd,
    };

    unsigned char sbackup[BLOCK_SIZE] = {
      0x00, 0x01, 0x02, 0x03, 0xff, 0xff, 0xff, 0xff, 0xff, 0x22, 0x22, 0x22, 0x22, 0x22, 0xdd,
    };

    unsigned char validator[BLOCK_SIZE] = {};

    for (size_t i = 0; i < BLOCK_SIZE; ++i) {
      validator[i] = iv[i] ^ subject[i];
    }

    Mode::CFB<BLOCK_SIZE>::encrypt(subject, iv, [&cipher](unsigned char *block) { cipher.encrypt(block); });

    t.byte_eq(subject, validator, sizeof(validator), "CFB Mode Block 15 Encrypt");

    Mode::CFB<BLOCK_SIZE>::decrypt(subject, iv_bkcup, [&cipher](unsigned char *block) { cipher.decrypt(block); });

    t.byte_eq(subject, sbackup, sizeof(sbackup), "CFB Mode Block 15 Decrypt");
    t.byte_eq(iv, iv_bkcup, sizeof(iv_bkcup), "CFB Mode IV Block 15");
    t.byte_neq(iv_original, iv, sizeof(iv_original), "CFB Mode Block 15 Altered");
  }

  std::cout << "CFB Mode Test Block 17 : \n";
  {

    constexpr size_t BLOCK_SIZE = 17;
    SudoCipher<BLOCK_SIZE> cipher;

    unsigned char iv_original[BLOCK_SIZE] = {
      0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0xba, 0xd2, 0xde, 0xed, 0xff, 0x11, 0x22, 0xcc, 0xf1,
    };

    unsigned char iv[BLOCK_SIZE] = {
      0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0xba, 0xd2, 0xde, 0xed, 0xff, 0x11, 0x22, 0xcc, 0xf1,
    };

    unsigned char iv_bkcup[BLOCK_SIZE] = {
      0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0xba, 0xd2, 0xde, 0xed, 0xff, 0x11, 0x22, 0xcc, 0xf1,
    };

    unsigned char subject[BLOCK_SIZE] = {
      0x00, 0x01, 0x02, 0x03, 0xff, 0xff, 0xff, 0xff, 0xff, 0x22, 0x22, 0x22, 0x22, 0x22, 0xdd, 0xfa, 0x0b,
    };

    unsigned char sbackup[BLOCK_SIZE] = {
      0x00, 0x01, 0x02, 0x03, 0xff, 0xff, 0xff, 0xff, 0xff, 0x22, 0x22, 0x22, 0x22, 0x22, 0xdd, 0xfa, 0x0b,
    };

    unsigned char validator[BLOCK_SIZE] = {};

    for (size_t i = 0; i < BLOCK_SIZE; ++i) {
      validator[i] = iv[i] ^ subject[i];
    }

    Mode::CFB<BLOCK_SIZE>::encrypt(subject, iv, [&cipher](unsigned char *block) { cipher.encrypt(block); });

    t.byte_eq(subject, validator, sizeof(validator), "CFB Mode Block 17 Encrypt");

    Mode::CFB<BLOCK_SIZE>::decrypt(subject, iv_bkcup, [&cipher](unsigned char *block) { cipher.decrypt(block); });

    t.byte_eq(subject, sbackup, sizeof(sbackup), "CFB Mode Block 17 Decrypt");
    t.byte_eq(iv, iv_bkcup, sizeof(iv_bkcup), "CFB Mode IV Block 17");
    t.byte_neq(iv_original, iv, sizeof(iv_original), "CFB Mode Block 17 Altered");
  }

  std::cout << "CFB Mode Test two 8 Block : \n";
  {
    constexpr size_t DATA_SIZE = 16;
    constexpr size_t BLOCK_SIZE = 8;
    SudoCipher<BLOCK_SIZE> cipher;

    constexpr size_t BLOCKS = DATA_SIZE / BLOCK_SIZE;

    unsigned char iv_original[BLOCK_SIZE] = {
      0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
    };

    unsigned char iv[BLOCK_SIZE] = {
      0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
    };

    unsigned char iv_bkcup[BLOCK_SIZE] = {
      0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
    };

    unsigned char subject[DATA_SIZE] = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0xfa, 0x7e,
    };

    unsigned char sbackup[DATA_SIZE] = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0xfa, 0x7e,
    };

    unsigned char validator[DATA_SIZE] = {};

    unsigned char iv_block[BLOCK_SIZE];
    std::memcpy(iv_block, iv, BLOCK_SIZE);

    for (size_t i = 0; i < BLOCKS; ++i) {
      for (size_t j = 0; j < BLOCK_SIZE; ++j) {
        validator[(i * BLOCK_SIZE) + j] = iv_block[j] ^ subject[(i * BLOCK_SIZE) + j];
        iv_block[j] = validator[(i * BLOCK_SIZE) + j];
      }
    }

    for (size_t i = 0; i < BLOCKS; i++) {
      Mode::CFB<BLOCK_SIZE>::encrypt(&subject[i * BLOCK_SIZE], iv, [&cipher](unsigned char *block) {
        cipher.encrypt(block);
      });
    }

    t.byte_eq(subject, validator, sizeof(validator), "CFB Mode 2 Block 8 Encrypt");

    for (size_t i = 0; i < BLOCKS; i++) {
      Mode::CFB<BLOCK_SIZE>::decrypt(&subject[i * BLOCK_SIZE], iv_bkcup, [&cipher](unsigned char *block) {
        cipher.decrypt(block);
      });
    }

    t.byte_eq(subject, sbackup, sizeof(sbackup), "CFB Mode 2 Block 8 Decrypt");
    t.byte_eq(iv, iv_bkcup, sizeof(iv_bkcup), "CFB Mode IV 2 Block 8");
    t.byte_neq(iv_original, iv, sizeof(iv_original), "CFB Mode 2 Block 8 Altered");
  }

  std::cout << "CFB Mode Test eight 2 Block : \n";
  {
    constexpr size_t DATA_SIZE = 16;
    constexpr size_t BLOCK_SIZE = 2;
    SudoCipher<BLOCK_SIZE> cipher;

    constexpr size_t BLOCKS = DATA_SIZE / BLOCK_SIZE;

    unsigned char iv_original[BLOCK_SIZE] = {
      0xde,
      0xad,
    };

    unsigned char iv[BLOCK_SIZE] = {
      0xde,
      0xad,
    };

    unsigned char iv_bkcup[BLOCK_SIZE] = {
      0xde,
      0xad,
    };

    unsigned char subject[DATA_SIZE] = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0xfa, 0x7e,
    };

    unsigned char sbackup[DATA_SIZE] = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0xfa, 0x7e,
    };

    unsigned char validator[DATA_SIZE] = {};

    unsigned char iv_block[BLOCK_SIZE];
    std::memcpy(iv_block, iv, BLOCK_SIZE);

    for (size_t i = 0; i < BLOCKS; ++i) {
      for (size_t j = 0; j < BLOCK_SIZE; ++j) {
        validator[(i * BLOCK_SIZE) + j] = iv_block[j] ^ subject[(i * BLOCK_SIZE) + j];
        iv_block[j] = validator[(i * BLOCK_SIZE) + j];
      }
    }

    for (size_t i = 0; i < BLOCKS; i++) {
      Mode::CFB<BLOCK_SIZE>::encrypt(&subject[i * BLOCK_SIZE], iv, [&cipher](unsigned char *block) {
        cipher.encrypt(block);
      });
    }

    t.byte_eq(subject, validator, sizeof(validator), "CFB Mode eight block of size 8 Encrypt");

    for (size_t i = 0; i < BLOCKS; i++) {
      Mode::CFB<BLOCK_SIZE>::decrypt(&subject[i * BLOCK_SIZE], iv_bkcup, [&cipher](unsigned char *block) {
        cipher.decrypt(block);
      });
    }

    t.byte_eq(subject, sbackup, sizeof(sbackup), "CFB Mode eight block of size 8 Decrypt");
    t.byte_eq(iv, iv_bkcup, sizeof(iv_bkcup), "CFB Mode IV eight block of size 8");
    t.byte_neq(iv_original, iv, sizeof(iv_original), "CFB Mode eight block of size 8 Altered");
  }

  return t.get_final_verdict();
}