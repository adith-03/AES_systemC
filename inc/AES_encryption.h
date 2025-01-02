#pragma once

#include <systemc.h>
#include "aes_constants.h"

class AES_encryption : public sc_module {
public:
  sc_in<sc_biguint<AES_SIZE>> plain_text{"plain_text"};
  sc_in<sc_biguint<AES_SIZE>> initial_key{"initial_key"};
  sc_out<sc_biguint<AES_SIZE>> cypher_text{"cypher_text"};

  sc_signal<sc_biguint<AES_SIZE>> round_in{"round_in"};

  sc_signal<sc_biguint<AES_SIZE>> SubByte_out{"SubByte_out"};
  sc_signal<sc_biguint<AES_SIZE>> shift_out{"shift_out"};
  sc_signal<sc_biguint<AES_SIZE>> mix_out{"mix_out"};
  sc_signal<sc_biguint<AES_SIZE>> round_out{"round_out"};

  sc_signal<sc_biguint<AES_SIZE>, SC_MANY_WRITERS> round_key{"round_key"};

  // Events for synchronisation
  sc_event sb{"subbytes"}, sr{"shiftRow"}, mc{"MixColumn"}, gen_key{"gen_key"},
    key_ready{"key_ready"};

  int current_round{};

  AES_encryption(sc_module_name name) : sc_module(name)
  {
    SC_THREAD(encryption);

    SC_METHOD(do_subbytes);
    sensitive << sb;
    dont_initialize();

    SC_METHOD(do_shifting);
    sensitive << sr;
    dont_initialize();

    SC_METHOD(mixcolumn);
    sensitive << mc;
    dont_initialize();

    SC_THREAD(key_expansion);
    sensitive << gen_key;
    dont_initialize();
  }

  void encryption();

  void do_subbytes();

  void do_shifting();


  void mixcolumn();

  void key_expansion();
};
