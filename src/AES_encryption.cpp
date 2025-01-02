#include "../inc/AES_encryption.h"

// Constructor which register the processes
AES_encryption::AES_encryption(sc_module_name name) : sc_module(name)
{
  SC_THREAD(encryption);

  SC_METHOD(subbytes);
  sensitive << sb;
  dont_initialize();

  SC_METHOD(shifting);
  sensitive << sr;
  dont_initialize();

  SC_METHOD(mixcolumn);
  sensitive << mc;
  dont_initialize();

  SC_THREAD(key_expansion);
  sensitive << gen_key;
  dont_initialize();
}


// Main encryption function that performs AES encryption
void AES_encryption::encryption()
{
  std::cout << "Plain text = " << plain_text << '\n';
  // Initial round key addition
  round_in = plain_text ^ initial_key;
  round_key.write(initial_key);
  wait(1, SC_NS);
  std::cout << "\nAfter initial AddRoundKey = " << round_in << '\n';

  for (current_round = 1; current_round <= TOTAL_ROUNDS; current_round++) {
    std::cout
      << "===========================================================\n";
    std::cout << "ROUND : " << std::dec << current_round << std::hex << "\n";
    std::cout << "Round input\t: " << round_in << '\n';

    // Perform SubBytes transformation
    sb.notify();
    wait(1, SC_NS);

    // Perform ShiftRows transformation
    sr.notify();
    wait(1, SC_NS);

    // Perform MixColumns transformation for all but the last round
    if (current_round != LAST_ROUND) {
      mc.notify();
      wait(1, SC_NS);
    }

    // Generate the current round key
    gen_key.notify();
    wait(key_ready);

    // AddRoundKey transformation
    if (current_round != LAST_ROUND) {
      round_out = mix_out.read() ^ round_key;
    } else {
      round_out = shift_out.read() ^ round_key;
    }
    wait(1, SC_NS);
    std::cout << "AddRoundKey Out\t: " << round_out << '\n';
    round_in.write(
      round_out.read()); // Pass current round's output to the next round

    wait(SC_ZERO_TIME); // Ensure signal updates

    std::cout
      << "===========================================================\n\n";
  }
  // Write the final encrypted output to cypher_text
  cypher_text.write(round_out);
}

// Performs the SubBytes transformation on the current input block
void AES_encryption::subbytes()
{
  // Input block to be transformed
  sc_biguint<AES_SIZE> sub_in;
  // Output block after SubBytes transformation
  sc_biguint<AES_SIZE> sub_out;
  sub_in = round_in.read();

  for (int i = AES_SIZE - 1; i >= 0; i -= BYTE) {
    sub_out.range(i, i - (BYTE - 1)) = sBox[static_cast<unsigned char>(
      sub_in.range(i, i - (BYTE - 1)).to_uint())];
  }
  SubByte_out.write(sub_out);
  std::cout << "SubBytes Out\t: " << sub_out << std::endl;
}
// Performs the ShiftRows transformation on the current block
void AES_encryption::shifting()
{
  // Input block from SubBytes output
  sc_biguint<AES_SIZE> in = SubByte_out.read();
  // Output block after ShiftRows transformation
  sc_biguint<AES_SIZE> out = SubByte_out.read();

  int shift_left{};
  int shift_size{};
  for (int i = AES_SIZE - 1; i >= 0; i -= 8) {
    if ((i + 1) % WORD == FIRST_ROW) {
      continue; // No shifting for the first row
    } else if ((i + 1) % WORD == SECOND_ROW) {
      shift_left = 1;
      shift_size = WORD * shift_left;

      if (i + shift_size > AES_SIZE) {
        out.range(i + shift_size - AES_SIZE,
                  i + shift_size - AES_SIZE - (BYTE - 1))
          = in.range(i, i - (BYTE - 1));
      } else {
        out.range(i + shift_size, i + shift_size - (BYTE - 1))
          = in.range(i, i - (BYTE - 1));
      }
    } else if ((i + 1) % WORD == THIRD_ROW) {
      shift_left = 2;
      shift_size = WORD * shift_left;

      if (i + shift_size > AES_SIZE) {
        out.range(i + shift_size - AES_SIZE,
                  i + shift_size - AES_SIZE - (BYTE - 1))
          = in.range(i, i - (BYTE - 1));
      } else {
        out.range(i + shift_size, i + shift_size - (BYTE - 1))
          = in.range(i, i - (BYTE - 1));
      }
    } else if ((i + 1) % WORD == FOURTH_ROW) {
      shift_left = 3;
      shift_size = WORD * shift_left;

      if (i + shift_size > AES_SIZE) {
        out.range(i + shift_size - AES_SIZE,
                  i + shift_size - AES_SIZE - (BYTE - 1))
          = in.range(i, i - (BYTE - 1));
      } else {
        out.range(i + shift_size, i + shift_size - (BYTE - 1))
          = in.range(i, i - (BYTE - 1));
      }
    }
  }

  shift_out.write(out);
  std::cout << "ShiftRows Out\t: " << out << '\n';
}

// Helper function to multiply a byte by 2 in GF(2^8)
uint8_t mult_by_2(uint8_t in)
{
  uint8_t res = in << 1;
  if ((in >> (BYTE - 1))) {
    res = res ^ 0x1B;
  }
  return res;
}

// Helper function to multiply a byte by 3 in GF(2^8)
uint8_t mult_by_3(uint8_t in)
{
  uint8_t res = mult_by_2(in);
  res         = res ^ in;
  return res;
}

// Performs the MixColumns transformation on the current block
void AES_encryption::mixcolumn()
{
  // Input block from ShiftRows output
  sc_biguint<AES_SIZE> in = shift_out.read();
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
      = (mult_by_2(c[i].range(31, 24))) ^ (mult_by_3(c[i].range(23, 16)))
        ^ (c[i].range(15, 8)) ^ (c[i].range((BYTE - 1), 0));
    index -= BYTE;

    out.range(index, index - (BYTE - 1))
      = (c[i].range(31, 24)) ^ (mult_by_2(c[i].range(23, 16)))
        ^ (mult_by_3(c[i].range(15, 8))) ^ (c[i].range((BYTE - 1), 0));
    index -= BYTE;

    out.range(index, index - (BYTE - 1))
      = (c[i].range(31, 24)) ^ (c[i].range(23, 16))
        ^ (mult_by_2(c[i].range(15, 8)))
        ^ (mult_by_3(c[i].range((BYTE - 1), 0)));
    index -= BYTE;

    out.range(index, index - (BYTE - 1))
      = (mult_by_3(c[i].range(31, 24))) ^ (c[i].range(23, 16))
        ^ (c[i].range(15, 8)) ^ (mult_by_2(c[i].range((BYTE - 1), 0)));
    index -= BYTE;
  }

  mix_out.write(out);
  std::cout << "MixColumns Out\t: " << out << "\n";
}

// Key expansion function to generate round keys for AES
void AES_encryption::key_expansion()
{
  sc_biguint<AES_SIZE> in;  // Input round key
  sc_biguint<AES_SIZE> out; // Output round key

  sc_uint<WORD> k[4];       // Words of the current round key
  sc_uint<WORD> out_key[4]; // Words of the next round key

  sc_uint<WORD> after_shifting; // Temporary storage after rotation
  sc_uint<WORD> after_subbytes; // Temporary storage after SubBytes

  while (1) {
    in = round_key.read();
    std::cout << "-----------------------------------------------------\n";
    std::cout << "Inside the Key Scheduler\n";

    std::cout << "Previous Key\t: " << in << "\n";

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
      = after_subbytes.range(31, 24) ^ ROUND_CONSTANTS[current_round - 1];


    // Calculate the next round key words
    out_key[0]
      = after_subbytes ^ k[0]; // XOR with the first word of the current key
    out_key[1] = k[1] ^ out_key[0]; // XOR with the second word
    out_key[2] = k[2] ^ out_key[1]; // XOR with the third word
    out_key[3] = k[3] ^ out_key[2]; // XOR with the fourth word

    // Combine the 4 words into a 128-bit output round key
    out = (out_key[0], out_key[1], out_key[2], out_key[3]);

    round_key.write(out);
    wait(SC_ZERO_TIME);
    std ::cout << "NEW ROUND KEY\t: " << round_key << "\n";
    std ::cout << "-----------------------------------------------------\n";

    // Notify that the new round key is ready for use
    key_ready.notify();

    // Wait for the event to notify to generate the next round key
    wait();
  }
}