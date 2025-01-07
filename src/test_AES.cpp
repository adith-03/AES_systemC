#include "../inc/AES_encryption.h"

int sc_main(int, char **)
{
  // Set output format to hexadecimal with base
  std::cout << std::hex << std::showbase;

  // Inputs for AES encryption
  sc_signal<sc_biguint<AES_SIZE>> plain_text{
    "plain_text"}; // AES_SIZE-bit signal for the plain text input
  sc_signal<sc_biguint<AES_SIZE>> initial_key{
    "initial_key"}; // AES_SIZE-bit signal for the initial key (encryption key)

  // Output for the cypher (encrypted text)
  sc_signal<sc_biguint<AES_SIZE>> cypher{
    "cypher"}; // AES_SIZE-bit signal to store the encrypted output (cypher text)

  // Expected result for verification (correct encrypted output)
  sc_biguint<AES_SIZE> expected_result;

  // Instantiate AES_encryption module
  AES_encryption Aes_en{"aes_en"};

  // Bind the input and output signals to the AES_encryption module
  Aes_en.plain_text.bind(plain_text);
  Aes_en.initial_key.bind(initial_key);
  Aes_en.cypher_text.bind(cypher);

  /*
  
*/


  sc_trace_file *tf = sc_create_vcd_trace_file("trace_ses_128");
  sc_trace(tf, plain_text, "plain_text");
  sc_trace(tf, initial_key, "key");
  sc_trace(tf, Aes_en.current_round, "Round");

  sc_trace(tf, Aes_en.round_in, "round_in");
  sc_trace(tf, Aes_en.SubByte_out, "SubByte_out");
  sc_trace(tf, Aes_en.shift_out, "shift_out");
  sc_trace(tf, Aes_en.mix_out, "mixcolumn_out");
  sc_trace(tf, Aes_en.round_out, "round_out");
  sc_trace(tf, cypher, "cypher_text");

  // Test case 1: Set plain text and initial key for encryption
  // plain text is "HAPPY NEW YEAR" in 128 bit
  plain_text.write(sc_biguint<AES_SIZE>(
    "0x4841505059204E455720594541520000")); // Set 128-bit plain text
  initial_key.write(
    "0x2b7e151628aed2a6abf7158809cf4f3c"); // Set 128-bit encryption key

  // Set the expected result after encryption (for verification)
  expected_result = "0x9261485fd26d53c5d9d4fd92df57f444";


  // Start the simulation
  sc_start(50, SC_NS);
  // Print out the final results
  std::cout << "FINAL STATS\n";
  std::cout << "Plain Text\t= " << plain_text.read() << "\n";
  std::cout << "Secret Key\t= " << initial_key.read() << "\n";
  std::cout << "Cypher Text\t= " << cypher << "\n";

  // Output the total simulation time
  std::cout << "\nTime = " << sc_time_stamp() << '\n';

  // Check if the encryption was successful by comparing the cypher text with the expected result
  if (cypher == expected_result) {
    std::cout << "ENCRYPTION SUCCESSFULL\n";
  } else {
    std::cout << "ENCRYPTION FAILED\n";
  }


  // Test case 2: Set plain text and initial key for encryption
  plain_text.write(sc_biguint<AES_SIZE>(
    "0x00112233445566778899aabbccddeeff")); // Set 128-bit plain text
  initial_key.write(
    "0x000102030405060708090a0b0c0d0e0f"); // Set 128-bit encryption key

  // Set the expected result after encryption (for verification)
  expected_result = "0x69c4e0d86a7b0430d8cdb78070b4c55a";

  sc_start(50, SC_NS);


  // Print out the final results
  std::cout << "FINAL STATS\n";
  std::cout << "Plain Text\t= " << plain_text.read() << "\n";
  std::cout << "Secret Key\t= " << initial_key.read() << "\n";
  std::cout << "Cypher Text\t= " << cypher << "\n";

  // Output the total simulation time
  std::cout << "\nTime = " << sc_time_stamp() << '\n';

  // Check if the encryption was successful by comparing the cypher text with the expected result
  if (cypher == expected_result) {
    std::cout << "ENCRYPTION SUCCESSFULL\n";
  } else {
    std::cout << "ENCRYPTION FAILED\n";
  }

  sc_close_vcd_trace_file(tf);

  return 0;
}
