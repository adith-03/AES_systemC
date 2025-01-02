#include "../inc/AES_encryption.h"

int sc_main(int, char **)
{
  std ::cout << std ::hex << std::showbase;
  sc_signal<sc_biguint<128>> plain_text{"plain_text"};
  sc_signal<sc_biguint<128>> initial_key{"initial_key"};

  sc_signal<sc_biguint<128>> cypher{"cypher"};

  sc_biguint<128> expected_result;

  AES_encryption Aes_en{"aes_en"};

  // Binding the inputs and outputs
  Aes_en.plain_text.bind(plain_text);
  Aes_en.initial_key.bind(initial_key);
  Aes_en.cypher_text.bind(cypher);

  // Test case
  plain_text.write(sc_biguint<128>("0x00112233445566778899aabbccddeeff"));
  initial_key.write("0x000102030405060708090a0b0c0d0e0f");

  expected_result = "0x69c4e0d86a7b0430d8cdb78070b4c55a";

  sc_start();

  std::cout << "FINAL STATS\n";
  std ::cout << "Plain Text\t= " << plain_text.read() << "\n";
  std ::cout << "Secret Key\t= " << initial_key.read() << "\n";
  std ::cout << "Cypher Text\t= " << cypher << "\n";


  std ::cout << "\nTime = " << sc_time_stamp() << '\n';
  if (cypher == expected_result) {
    std ::cout << "ENCRYPTION SUCCESSFULL\n";
  } else {
    std ::cout << "ENCRYPTION FAILED\n";
  }
  return 0;
}