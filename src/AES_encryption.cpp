#include "AES_encryption.h"

uint8_t mult_by_2(uint8_t in)
{
  uint8_t res = in << 1;
  if ((in >> (BYTE - 1))) {
    res = res ^ 0x1B;
  }
  return res;
}

uint8_t mult_by_3(uint8_t in)
{
  uint8_t res = mult_by_2(in);

  res = res ^ in;

  return res;
}


void AES_encryption::encryption()
{
  std ::cout << "Plain text = " << plain_text << '\n';
  // initial round key
  round_in = plain_text ^ initial_key;
  round_key.write(initial_key);
  wait(1, SC_NS);
  std ::cout << "\nAfter initial Addroundkey = " << round_in << '\n';

  for (current_round = 1; current_round <= TOTAL_ROUNDS; current_round++) {
    std::cout
      << "===========================================================\n";
    std ::cout << "ROUND : " << std ::dec << current_round << std::hex << "\n";
    std ::cout << "Round input\t: " << round_in << '\n';

    // SubBytes
    sb.notify();
    wait(1, SC_NS);

    // ShiftRow
    sr.notify();
    wait(1, SC_NS);

    // Last Round doesn't have MixColumn
    if (current_round != LAST_ROUND) {
      mc.notify();
      wait(1, SC_NS);
    }


    // Get the current round key
    gen_key.notify();

    wait(key_ready);

    // Add roundkey
    if (current_round != LAST_ROUND) {
      round_out = mix_out.read() ^ round_key;
    } else {
      round_out = shift_out.read() ^ round_key;
    }
    wait(1, SC_NS);
    std ::cout << "AddRoundkey Out\t: " << round_out << '\n';
    round_in.write(
      round_out.read()); // current rounds output as next rounds input

    wait(SC_ZERO_TIME); // for updating the signal

    std ::cout
      << "===========================================================\n\n";
  }
  cypher_text.write(round_out);
}


void AES_encryption::do_subbytes()
{
  sc_biguint<AES_SIZE> sub_in;
  sc_biguint<AES_SIZE> sub_out;
  sub_in = round_in.read();

  for (int i = AES_SIZE - 1; i >= 0; i -= BYTE) {
    sub_out.range(i, i - (BYTE - 1)) = sBox[static_cast<unsigned char>(
      sub_in.range(i, i - (BYTE - 1)).to_uint())];
  }
  SubByte_out.write(sub_out);
  std::cout << "Subbytes out\t: " << sub_out << std::endl;
}


void AES_encryption::do_shifting()
{
  sc_biguint<AES_SIZE> in  = SubByte_out.read();
  sc_biguint<AES_SIZE> out = SubByte_out.read();

  int start = AES_SIZE - 1;
  int shift_left{};
  int shift_size{};
  for (int i = AES_SIZE - 1; i >= 0; i -= 8) {
    if ((i + 1) % WORD == FIRST_ROW) {
      continue;
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
  std ::cout << "Shiftrow out\t: " << out << '\n';
}

void AES_encryption::mixcolumn()
{
  sc_biguint<AES_SIZE> in = shift_out.read();
  sc_biguint<AES_SIZE> out;
  sc_uint<WORD> c[4];

  c[0] = in.range(127, 96);
  c[1] = in.range(95, 64);
  c[2] = in.range(63, 32);
  c[3] = in.range(31, 0);

  int index = AES_SIZE - 1;
  for (int i = 0; i < 4; i++) {
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
  std ::cout << "Mixcolumn out\t: " << out << "\n";
}

void AES_encryption::key_expansion()
{
  sc_biguint<AES_SIZE> in;
  sc_biguint<AES_SIZE> out;

  sc_uint<WORD> k[4];
  sc_uint<WORD> out_key[4];

  sc_uint<WORD> after_shifting;
  sc_uint<WORD> after_subbytes;

  while (1) {
    in = round_key.read();
    std ::cout << "-----------------------------------------------------\n";
    std ::cout << "Inside the key scheduler\n";

    std ::cout << "PREVIOUS KEY\t: " << in << "\n";
    k[0] = in.range(127, 96);
    k[1] = in.range(95, 64);
    k[2] = in.range(63, 32);
    k[3] = in.range(31, 0);

    // using last word ( k[3] ) we will create the next keys words

    // use concatination operator

    after_shifting = (k[3].range(23, 16),
                      k[3].range(15, 8),
                      k[3].range(7, 0),
                      k[3].range(31, 24));

    after_subbytes.range(31, 24) = sBox[static_cast<unsigned char>(
      after_shifting.range(31, 24).to_uint())];
    after_subbytes.range(23, 16) = sBox[static_cast<unsigned char>(
      after_shifting.range(23, 16).to_uint())];
    after_subbytes.range(15, 8)
      = sBox[static_cast<unsigned char>(after_shifting.range(15, 8).to_uint())];
    after_subbytes.range((BYTE - 1), 0) = sBox[static_cast<unsigned char>(
      after_shifting.range((BYTE - 1), 0).to_uint())];


    after_subbytes.range(31, 24)
      = after_subbytes.range(31, 24) ^ ROUND_CONSTANTS[current_round - 1];


    out_key[0] = after_subbytes ^ k[0];
    out_key[1] = k[1] ^ out_key[0];
    out_key[2] = k[2] ^ out_key[1];
    out_key[3] = k[3] ^ out_key[2];

    out = (out_key[0], out_key[1], out_key[2], out_key[3]);

    round_key.write(out);
    wait(SC_ZERO_TIME);
    std ::cout << "NEW ROUND KEY\t: " << round_key << "\n";
    std ::cout << "-----------------------------------------------------\n";

    key_ready.notify(); // notify that new key is ready

    wait(); // wait for the event to notify
  }
}