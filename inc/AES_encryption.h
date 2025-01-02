#pragma once

#include <systemc.h>
#include "aes_constants.h"

/**
 * @class AES_encryption
 * @brief A SystemC module for AES encryption.
 *
 * This class models the AES encryption process, including SubBytes, ShiftRows,
 * MixColumns,Addroundkey and Key Expansion stages. It utilizes SystemC signals and events
 * for synchronization between stages.
 */
class AES_encryption : public sc_module {
public:
  /**
   * @brief Input ports for plaintext and initial key.
   *
   * plain_text: The input port for the plaintext to be encrypted.
   * initial_key: The input port for the initial AES key.
   */
  sc_in<sc_biguint<AES_SIZE>> plain_text{"plain_text"};
  sc_in<sc_biguint<AES_SIZE>> initial_key{"initial_key"};

  /**
   * @brief Output port for the final encrypted ciphertext.
   */
  sc_out<sc_biguint<AES_SIZE>> cypher_text{"cypher_text"};

  /**
   * @brief Intermediate signals used during encryption.
   *
   * round_in: Input to the current round of AES encryption.
   * SubByte_out: Output of the SubBytes transformation.
   * shift_out: Output of the ShiftRows transformation.
   * mix_out: Output of the MixColumns transformation.
   * round_out: Output of the current round of encryption.
   * round_key: Current round key used in encryption (with multiple writers).
   */
  sc_signal<sc_biguint<AES_SIZE>> round_in{"round_in"};
  sc_signal<sc_biguint<AES_SIZE>> SubByte_out{"SubByte_out"};
  sc_signal<sc_biguint<AES_SIZE>> shift_out{"shift_out"};
  sc_signal<sc_biguint<AES_SIZE>> mix_out{"mix_out"};
  sc_signal<sc_biguint<AES_SIZE>> round_out{"round_out"};
  sc_signal<sc_biguint<AES_SIZE>, SC_MANY_WRITERS> round_key{"round_key"};

  /**
   * @brief Events used for synchronization between different stages of encryption.
   *
   * sb: Event to trigger the SubBytes stage.
   * sr: Event to trigger the ShiftRows stage.
   * mc: Event to trigger the MixColumns stage.
   * gen_key: Event to trigger key expansion.
   * key_ready: Event indicating that the round key is ready.
   */
  sc_event sb{"subbytes"}, sr{"shiftRow"}, mc{"MixColumn"}, gen_key{"gen_key"},
    key_ready{"key_ready"};

  /**
   * @brief The current round number of the AES encryption process.
   */
  int current_round{};

  /**
   * @brief Constructor for the AES_encryption module.
   * @param name The name of the module.
   */
  AES_encryption(sc_module_name name);

  /**
   * @brief The main encryption process, coordinating all stages.
   */
  void encryption();

  /**
   * @brief Performs the SubBytes transformation.
   */
  void subbytes();

  /**
   * @brief Performs the ShiftRows transformation.
   */
  void shifting();

  /**
   * @brief Performs the MixColumns transformation.
   */
  void mixcolumn();

  /**
   * @brief Handles the key expansion process.
   */
  void key_expansion();
};
