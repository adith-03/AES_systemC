#include "../inc/AES_decryption.h"

AES_decryption::AES_decryption(sc_module_name name)
  : sc_module(name), Round_keys(TOTAL_ROUNDS + 1)
{
  SC_THREAD(decryption);

  SC_METHOD(inv_subbytes);
  sensitive << i_sb;
  dont_initialize();

  SC_METHOD(inv_shifting);
  sensitive << i_sr;
  dont_initialize();

  SC_METHOD(inv_mixcolumn);
  sensitive << i_mc;
  dont_initialize();
}

void AES_decryption::decryption()
{
  wait(cypher_text.default_event());

  std ::cout << "\vAES DECRYPTION UNIT\n\n";
  key_expansion(); // create all 10 keys

  // while (1) {
  std::cout << "Cypher text = " << cypher_text << '\n';
  // Initial round key addition
  round_in = cypher_text ^ Round_keys[TOTAL_ROUNDS];
  round_key.write(secret_key);
  wait(1, SC_NS);
  std::cout << "\nAfter initial AddRoundKey          = " << round_in << '\n';

  for (current_round = 1; current_round <= TOTAL_ROUNDS; current_round++) {
    std::cout
      << "===========================================================\n";
    std::cout << "ROUND : " << std::dec << current_round << std::hex << "\n";
    std::cout << "Round input\t: " << round_in << '\n';

    // Perform Inverse ShiftRows transformation
    i_sr.notify();
    wait(1, SC_NS);

    // Perform Inverse subbytes
    i_sb.notify();
    wait(1, SC_NS);


    // AddRoundKey transformation
    std ::cout << "Key\t\t= " << Round_keys[TOTAL_ROUNDS - current_round]
               << '\n';
    inv_add_round_out
      = inv_subByte_out.read() ^ Round_keys[TOTAL_ROUNDS - current_round];

    wait(1, SC_NS);
    std::cout << "AddRoundKey Out\t: " << inv_add_round_out << '\n';

    // Perform inverse MixColumns transformation for all but the last round
    if (current_round != LAST_ROUND) {
      i_mc.notify();
      wait(1, SC_NS);
      round_in.write(
        inv_mix_out.read()); // Pass current round's output to the next round
    } else {
      round_in.write(
        inv_add_round_out
          .read()); // Pass current round's output to the next round
    }

    wait(SC_ZERO_TIME); // Ensure signal updates

    std::cout
      << "===========================================================\n\n";
  }


  // Write the final encrypted output to cypher_text
  plain_text.write(inv_add_round_out);
  wait(SC_ZERO_TIME);

  std ::cout << "Decrypted text = " << plain_text << '\n';
  std ::cout << "DECRYPTION COMPLETED\n";

  //   wait(cypher_text.default_event() | secret_key.default_event());
  // }
}


void AES_decryption::inv_subbytes()
{
  // Input block to be transformed
  sc_biguint<AES_SIZE> i_sub_in;
  // Output block after SubBytes transformation
  sc_biguint<AES_SIZE> i_sub_out;
  i_sub_in = inv_shift_out.read();

  for (int i = AES_SIZE - 1; i >= 0; i -= BYTE) {
    i_sub_out.range(i, i - (BYTE - 1)) = invSBox[static_cast<unsigned char>(
      i_sub_in.range(i, i - (BYTE - 1)).to_uint())];
  }
  inv_subByte_out.write(i_sub_out);
  std::cout << "inv SubBytes Out\t: " << i_sub_out << std::endl;
}

void AES_decryption::inv_shifting()
{
  // Input block from inverse SubBytes output
  sc_biguint<AES_SIZE> in = round_in.read();
  // Output block after inverse ShiftRows transformation
  sc_biguint<AES_SIZE> out = round_in.read();

  int shift_right{};
  int shift_size{};
  for (int i = AES_SIZE - 1; i >= 0; i -= 8) {
    if ((i + 1) % WORD == FIRST_ROW) {
      continue; // No shifting for the first row
    } else if ((i + 1) % WORD == SECOND_ROW) {
      shift_right = 1;
      shift_size  = WORD * shift_right;

      if (i - shift_size < 0) {
        out.range(i - shift_size + AES_SIZE,
                  i - shift_size + AES_SIZE - (BYTE - 1))
          = in.range(i, i - (BYTE - 1));
      } else {
        out.range(i - shift_size, i - shift_size - (BYTE - 1))
          = in.range(i, i - (BYTE - 1));
      }
    } else if ((i + 1) % WORD == THIRD_ROW) {
      shift_right = 2;
      shift_size  = WORD * shift_right;

      if (i - shift_size < 0) {
        out.range(i - shift_size + AES_SIZE,
                  i - shift_size + AES_SIZE - (BYTE - 1))
          = in.range(i, i - (BYTE - 1));
      } else {
        out.range(i - shift_size, i - shift_size - (BYTE - 1))
          = in.range(i, i - (BYTE - 1));
      }
    } else if ((i + 1) % WORD == FOURTH_ROW) {
      shift_right = 3;
      shift_size  = WORD * shift_right;

      if (i - shift_size < 0) {
        out.range(i - shift_size + AES_SIZE,
                  i - shift_size + AES_SIZE - (BYTE - 1))
          = in.range(i, i - (BYTE - 1));
      } else {
        out.range(i - shift_size, i - shift_size - (BYTE - 1))
          = in.range(i, i - (BYTE - 1));
      }
    }
  }

  inv_shift_out.write(out);
  std::cout << "inv ShiftRows Out\t: " << out << '\n';
}

// Helper functions for inverse Mixcolumn calculations
uint8_t mult_by_0E(uint8_t in)
{
  // 0x0E=00001110
  uint8_t res{};
  /* Left shift by 1 */
  uint8_t s1 = in << 1;
  if ((in >> (BYTE - 1))) {
    s1 = s1 ^ 0x1B;
  }
  // left shift by 2
  uint8_t s2 = s1 << 1;
  if ((s1 >> (BYTE - 1))) {
    s2 = s2 ^ 0x1B;
  }
  // left shift by 3
  uint8_t s3 = s2 << 1;
  if ((s2 >> (BYTE - 1))) {
    s3 = s3 ^ 0x1B;
  }

  res = s1 ^ s2 ^ s3;
  return res;
}

uint8_t mult_by_0B(uint8_t in)
{
  // 0x0B=00001011

  uint8_t res{};
  /* Left shift by 1 */
  uint8_t s1 = in << 1;
  if ((in >> (BYTE - 1))) {
    s1 = s1 ^ 0x1B;
  }
  // left shift by 2
  uint8_t s2 = s1 << 1;
  if ((s1 >> (BYTE - 1))) {
    s2 = s2 ^ 0x1B;
  }
  // left shift by 3
  uint8_t s3 = s2 << 1;
  if ((s2 >> (BYTE - 1))) {
    s3 = s3 ^ 0x1B;
  }

  res = in ^ s1 ^ s3;
  return res;
}

uint8_t mult_by_0D(uint8_t in)
{
  // 0x0D=00001101

  uint8_t res{};
  /* Left shift by 1 */
  uint8_t s1 = in << 1;
  if ((in >> (BYTE - 1))) {
    s1 = s1 ^ 0x1B;
  }
  // left shift by 2
  uint8_t s2 = s1 << 1;
  if ((s1 >> (BYTE - 1))) {
    s2 = s2 ^ 0x1B;
  }
  // left shift by 3
  uint8_t s3 = s2 << 1;
  if ((s2 >> (BYTE - 1))) {
    s3 = s3 ^ 0x1B;
  }

  res = in ^ s2 ^ s3;
  return res;
}

uint8_t mult_by_09(uint8_t in)
{
  // 0x09=00001001

  uint8_t res{};
  /* Left shift by 1 */
  uint8_t s1 = in << 1;
  if ((in >> (BYTE - 1))) {
    s1 = s1 ^ 0x1B;
  }
  // left shift by 2
  uint8_t s2 = s1 << 1;
  if ((s1 >> (BYTE - 1))) {
    s2 = s2 ^ 0x1B;
  }
  // left shift by 3
  uint8_t s3 = s2 << 1;
  if ((s2 >> (BYTE - 1))) {
    s3 = s3 ^ 0x1B;
  }

  res = in ^ s3;
  return res;
}

void AES_decryption::inv_mixcolumn()
{
  // Input block from ShiftRows output
  sc_biguint<AES_SIZE> in = inv_add_round_out.read();
  // Output block after MixColumns transformation
  sc_biguint<AES_SIZE> out;
  sc_uint<WORD> c[4]; // Array to store 4 columns of the input block

  // Divide input into 4 columns
  c[0] = in.range(127, 96);
  c[1] = in.range(95, 64);
  c[2] = in.range(63, 32);
  c[3] = in.range(31, 0);

  int index = AES_SIZE - 1;
  for (int i = 0; i < 4; i++) {
    // Perform GF(2^8) multiplication and XOR for each byte in the column
    out.range(index, index - (BYTE - 1))
      = (mult_by_0E(c[i].range(31, 24))) ^ (mult_by_0B(c[i].range(23, 16)))
        ^ (mult_by_0D(c[i].range(15, 8)))
        ^ (mult_by_09(c[i].range((BYTE - 1), 0)));
    index -= BYTE;

    out.range(index, index - (BYTE - 1))
      = (mult_by_09(c[i].range(31, 24))) ^ (mult_by_0E(c[i].range(23, 16)))
        ^ (mult_by_0B(c[i].range(15, 8)))
        ^ (mult_by_0D(c[i].range((BYTE - 1), 0)));
    index -= BYTE;

    out.range(index, index - (BYTE - 1))
      = (mult_by_0D(c[i].range(31, 24))) ^ (mult_by_09(c[i].range(23, 16)))
        ^ (mult_by_0E(c[i].range(15, 8)))
        ^ (mult_by_0B(c[i].range((BYTE - 1), 0)));
    index -= BYTE;

    out.range(index, index - (BYTE - 1))
      = (mult_by_0B(c[i].range(31, 24))) ^ (mult_by_0D(c[i].range(23, 16)))
        ^ (mult_by_09(c[i].range(15, 8)))
        ^ (mult_by_0E(c[i].range((BYTE - 1), 0)));
    index -= BYTE;
  }

  inv_mix_out.write(out);
  std::cout << "inv MixColumns Out\t: " << out << "\n";
}


// Key expansion function to generate round keys for AES
void AES_decryption::key_expansion()
{
  sc_biguint<AES_SIZE> in;  // Input round key
  sc_biguint<AES_SIZE> out; // Output round key

  sc_uint<WORD> k[4];       // Words of the current round key
  sc_uint<WORD> out_key[4]; // Words of the next round key

  sc_uint<WORD> after_shifting; // Temporary storage after rotation
  sc_uint<WORD> after_subbytes; // Temporary storage after SubBytes

  Round_keys[0] = secret_key.read(); // initial key

  for (int i{}; i < TOTAL_ROUNDS; i++) {
    in = Round_keys[i];

    // Split the input round key into 4 words (32 bits each)
    k[0] = in.range(127, 96); // First word of the current round key
    k[1] = in.range(95, 64);  // Second word of the current round key
    k[2] = in.range(63, 32);  // Third word of the current round key
    k[3] = in.range(31, 0);   // Fourth word of the current round key

    // Generate the next round key using the previous key

    // Perform word rotation on the last word
    after_shifting = (k[3].range(23, 16),
                      k[3].range(15, 8),
                      k[3].range(7, 0),
                      k[3].range(31, 24));


    // Apply SubBytes transformation to the rotated word
    after_subbytes.range(31, 24) = sBox[static_cast<unsigned char>(
      after_shifting.range(31, 24).to_uint())];
    after_subbytes.range(23, 16) = sBox[static_cast<unsigned char>(
      after_shifting.range(23, 16).to_uint())];
    after_subbytes.range(15, 8)
      = sBox[static_cast<unsigned char>(after_shifting.range(15, 8).to_uint())];
    after_subbytes.range((BYTE - 1), 0) = sBox[static_cast<unsigned char>(
      after_shifting.range((BYTE - 1), 0).to_uint())];

    // XOR the result of SubBytes with the round constant for the current round
    after_subbytes.range(31, 24)
      = after_subbytes.range(31, 24) ^ ROUND_CONSTANTS[i];

    // Calculate the next round key words
    out_key[0]
      = after_subbytes ^ k[0]; // XOR with the first word of the current key
    out_key[1] = k[1] ^ out_key[0]; // XOR with the second word
    out_key[2] = k[2] ^ out_key[1]; // XOR with the third word
    out_key[3] = k[3] ^ out_key[2]; // XOR with the fourth word

    // Combine the 4 words into a 128-bit output round key
    out = (out_key[0], out_key[1], out_key[2], out_key[3]);


    Round_keys[i + 1] = out;
  }
}