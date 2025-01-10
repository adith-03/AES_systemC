#pragma once

#include <systemc.h>
#include "aes_constants.h"

/**
 * @class AES_decryption
 * @brief A SystemC module for AES decryption.
 *
 * This class models the AES decryption process, including inverse SubBytes, inverse ShiftRows,
 * inverse MixColumns,Addroundkey and Key Expansion stages. It utilizes SystemC signals and events
 * for synchronization between stages.
 */
class AES_decryption : public sc_module {
public:
  /**
   * @brief Input ports for cypher_text and secret_key.
   *
   * cypher_text: The input port for the cyphertext to be decrypted.
   * secret_key: The input port for the AES key.
   */
  sc_in<sc_biguint<AES_SIZE>> cypher_text{"cypher_text"};
  sc_in<sc_biguint<AES_SIZE>> secret_key{"secret_key"};

  /**
   * @brief Output port for the final decrypted text.
   */
  sc_out<sc_biguint<AES_SIZE>> plain_text{"plain_text"};


  /**
   * @brief Intermediate signals used during decryption.
   *
   * round_in: Input to the current round of AES decryption.
   * inv_subByte_out: Output of the inverse SubBytes transformation.
   * inv_shift_out: Output of the inverse ShiftRows transformation.
   * inv_mix_out: Output of the inverse MixColumns transformation.
   * inv_add_round_out: Output of the add round key.
   */
  sc_signal<sc_biguint<AES_SIZE>> round_in{"round_in"};
  sc_signal<sc_biguint<AES_SIZE>> inv_subByte_out{"inv_subByte_out"};
  sc_signal<sc_biguint<AES_SIZE>> inv_shift_out{"inv_shift_out"};
  sc_signal<sc_biguint<AES_SIZE>> inv_mix_out{"inv_mix_out"};
  sc_signal<sc_biguint<AES_SIZE>> inv_add_round_out{"inv_add_round_out"};


  /**
   * @brief Events used for synchronization between different stages of decryption.
   *
   * i_sb: Event to trigger the inverse SubBytes stage.
   * i_sr: Event to trigger the inverse ShiftRows stage.
   * i_mc: Event to trigger the inverse MixColumns stage.
   */
  sc_event i_sb{"inv_subBytes"}, i_sr{"inv_shiftRow"}, i_mc{"inv_MixColumn"};

  /**
   * @brief Constructor for the AES_decryption module.
   * @param name The name of the module.
   */
  AES_decryption(sc_module_name name); // constructor

  /**
   * @brief The main decryption process, coordinating all stages.
   */
  void decryption();

  /**
   * @brief Performs the inverse SubBytes transformation.
   */
  void inv_subbytes();

  /**
   * @brief Performs the inverse ShiftRows transformation.
   */
  void inv_shifting();

  /**
   * @brief Performs the inverse MixColumns transformation.
   */
  void inv_mixcolumn();

  /**
   * @brief Generate all keys and store in a vector
   */
  void key_expansion(); //

private:
  /**
   * @brief The current round number of the AES decryption process.
   */
  int current_round{};

  /**
   * @brief The vector to store initial key and all 10 round keys in AES decryption process.
   */
  std ::vector<sc_biguint<AES_SIZE>> Round_keys;
};
