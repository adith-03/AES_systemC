# AES Encryption in SystemC

## Overview
This project implements the AES encryption algorithm using SystemC. The AES encryption process follows the standard AES algorithm, which operates on a 128-bit block of data using a 128-bit key. The project includes key expansion, substitution, shifting, and XOR operations that are required for the encryption process.

## Project Structure
The project contains the following directory structure:
.
├── inc
│   ├── aes_constants.h
│   └── AES_encryption.h
├── Makefile
├── nistAES.pdf
├── README.md
└── src
    ├── AES_encryption.cpp
    └── test_AES.cpp


- **`inc/`**: Contains the header files.
  - `aes_constants.h`: Defines constants for AES operations.
  - `AES_encryption.h`: Contains the class definition for AES encryption.
  
- **`src/`**: Contains the source files.
  - `AES_encryption.cpp`: Contains the main implementation of the AES encryption algorithm.
  - `test_AES.cpp`: A testbench file for verifying the AES encryption implementation.

- **`Makefile`**: The build script to compile and simulate the project.
- **`nistAES.pdf`**: A reference document on the AES algorithm for further understanding of the standard.

## Requirements
To run this project, you need to have the following:
- **SystemC**: A library for system-level modeling and simulation. It is required to compile and simulate the design.
- **C++ Compiler**: For compiling the source code.

Ensure that you have the SystemC library installed and properly configured in your environment.

## Building the Project
Use the `Makefile` to compile and build the project:
`make`

This will compile the source files, link them with the SystemC library, and create the executable.

## Running the Simulation
After building the project, run the simulation using:
`./aes_128`
or do
`make run`

The program will simulate the AES encryption for the given plaintext and key, and display the results in hexadecimal format.

## Key Features
- **AES Key Expansion**: Implements the key expansion algorithm to generate round keys for the AES algorithm.
- **SubBytes, ShiftRows, MixColumns, AddRoundKey**: All core AES transformations are implemented.
- **Testbench**: Includes a testbench for verifying the AES encryption against known results.

## Test Case
The test case uses the following inputs:
- **Plaintext**: `0x00112233445566778899aabbccddeeff`
- **Initial Key**: `0x000102030405060708090a0b0c0d0e0f`

The expected output after encryption is:
`Cypher Text: 0x69c4e0d86a7b0430d8cdb78070b4c55a`

## Output Format
- The plaintext, secret key, and resulting cypher text are printed in hexadecimal format with the `0x` prefix.
- The success/failure status of the encryption is also displayed.

Example Output:

`FINAL STATS Plain Text = 0x00112233445566778899aabbccddeeff`

`Secret Key = 0x000102030405060708090a0b0c0d0e0f` 

`Cypher Text = 0x69c4e0d86a7b0430d8cdb78070b4c55a`

`ENCRYPTION SUCCESSFUL`


## Authors
- **Adith**: Developer of this AES encryption module and testbench.
