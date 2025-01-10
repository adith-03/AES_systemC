#include "../inc/AES_encryption.h"
#include "../inc/AES_decryption.h"

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

  // Output of the decryption
  sc_signal<sc_biguint<AES_SIZE>> decrypted_text{"decrypted_text"};

  // Expected result for verification (correct encrypted output)
  sc_biguint<AES_SIZE> expected_result;

  // Instantiate AES_encryption module
  AES_encryption Aes_en{"aes_en"};

  // Instantiate decryption unit
  AES_decryption Aes_dec{"Aes_dec"};

  // Bind the input and output signals to the AES_encryption module
  Aes_en.plain_text.bind(plain_text);
  Aes_en.initial_key.bind(initial_key);
  Aes_en.cypher_text.bind(cypher);

  // Bind the input and output signals to the AES_decryption module
  Aes_dec.cypher_text.bind(cypher);
  Aes_dec.secret_key.bind(initial_key);
  Aes_dec.plain_text.bind(decrypted_text);

  // // Create the Trace file
  sc_trace_file *tf = sc_create_vcd_trace_file("aes_trace");
  tf->set_time_unit(1, SC_PS); // set tracing timescale unit
  sc_trace(tf, plain_text, "plain_text");
  sc_trace(tf, initial_key, "key");
  sc_trace(tf, cypher, "cypher_text");
  sc_trace(tf, decrypted_text, "decrypted_text");


  // /*****************************************************************
  //  * Test case 1: Set plain text and initial key for encryption
  //  *
  //  * Plain text and Key taken from the example given in nistAES.pdf
  // ******************************************************************/
  // std ::cout << "TEST CASE 1\n\n";
  // plain_text.write(sc_biguint<AES_SIZE>(
  //   "0x00112233445566778899aabbccddeeff")); // Set 128-bit plain text
  // initial_key.write(
  //   "0x000102030405060708090a0b0c0d0e0f"); // Set 128-bit encryption key

  // // Set the expected result after encryption (for verification)
  // expected_result = "0x69c4e0d86a7b0430d8cdb78070b4c55a";

  // sc_start(100, SC_NS);


  // // Output the total simulation time
  // std::cout << "\nTime = " << sc_time_stamp() << '\n';

  // // Check if the encryption was successful by comparing the cypher text with the expected result
  // if (cypher == expected_result) {
  //   std::cout << "ENCRYPTION SUCCESSFULL\n";
  // } else {
  //   std::cout << "ENCRYPTION FAILED\n";
  // }


  // if (decrypted_text == plain_text) {
  //   std::cout << "DECRYPTION SUCCESSFULL\n";
  //   std::cout << "\nAES 128 PROCESS SUCCESSFULL\n\n";
  // } else {
  //   std::cout << "DECRYPTION SUCCESSFULL\n";
  //   std::cout << "\nAES 128 PROCESS FAILED\n\n";
  // }

  // // Print out the final results
  // std::cout << "FINAL STATS\n";
  // std::cout << "Plain Text\t= " << plain_text.read() << "\n";
  // std::cout << "Secret Key\t= " << initial_key.read() << "\n";
  // std::cout << "Cypher Text\t= " << cypher << "\n";
  // std::cout << "Decrpted text\t= " << decrypted_text << "\n";


  /*****************************************************************
   * Test case 2: Set plain text and initial key for encryption
   * 
   * Plain text is "HAPPY NEW YEAR" in 128 bit
  ******************************************************************/
  std ::cout << "\nTEST CASE 2\n\n";
  plain_text.write(sc_biguint<AES_SIZE>(
    "0x4841505059204E455720594541520000")); // Set 128-bit plain text
  initial_key.write(
    "0x2b7e151628aed2a6abf7158809cf4f3c"); // Set 128-bit encryption key

  // Set the expected result after encryption (for verification)
  expected_result = "0x9261485fd26d53c5d9d4fd92df57f444";

  sc_start(100, SC_NS);


  // Check if the encryption was successful by comparing the cypher text with the expected result
  if (cypher == expected_result) {
    std::cout << "ENCRYPTION SUCCESSFULL\n";
  } else {
    std::cout << "ENCRYPTION FAILED\n";
  }


  if (decrypted_text == plain_text) {
    std::cout << "DECRYPTION SUCCESSFULL\n";
    std::cout << "\nAES 128 PROCESS SUCCESSFULL\n\n";
  } else {
    std::cout << "DECRYPTION FAILED\n";
    std::cout << "\nAES 128 PROCESS FAILED\n\n";
  }

  // Print out the final results
  std::cout << "FINAL STATS\n";
  std::cout << "Plain Text\t= " << plain_text.read() << "\n";
  std::cout << "Secret Key\t= " << initial_key.read() << "\n";
  std::cout << "Cypher Text\t= " << cypher << "\n";
  std::cout << "Decrpted text\t= " << decrypted_text << "\n";

  sc_close_vcd_trace_file(tf); // Close the trace file

  return 0;
}
