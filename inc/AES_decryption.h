#include <systemc.h>
#include "aes_constants.h"

class AES_decryption : public sc_module {
public:
  sc_in<sc_biguint<AES_SIZE>> cypher_text{"cypher_text"};
  sc_in<sc_biguint<AES_SIZE>> secret_key{"secret_key"};


  sc_out<sc_biguint<AES_SIZE>> plain_text{"plain_text"};

  sc_signal<sc_biguint<AES_SIZE>> round_in{"round_in"};
  sc_signal<sc_biguint<AES_SIZE>> inv_subByte_out{"inv_subByte_out"};
  sc_signal<sc_biguint<AES_SIZE>> inv_shift_out{"inv_shift_out"};
  sc_signal<sc_biguint<AES_SIZE>> inv_mix_out{"inv_mix_out"};
  sc_signal<sc_biguint<AES_SIZE>> inv_add_round_out{"inv_add_round_out"};
  sc_signal<sc_biguint<AES_SIZE>, SC_MANY_WRITERS> round_key{"round_key"};

  sc_event i_sb{"inv_subBytes"}, i_sr{"inv_shiftRow"}, i_mc{"inv_MixColumn"},
    gen_key{"gen_key"}, key_ready{"key_ready"};


  AES_decryption(sc_module_name name); // constructor

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

  void key_expansion();


private:
  int current_round{};
  std ::vector<sc_biguint<AES_SIZE>> Round_keys;
};
