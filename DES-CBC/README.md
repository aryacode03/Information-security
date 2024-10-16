# DES-CBC Encryption and Decryption in Python

This is a Python implementation of the DES (Data Encryption Standard) with CBC (Cipher Block Chaining) mode of operation, adapted from a C implementation by tayyipozturk. DES is a symmetric-key block cipher that encrypts data in fixed-size blocks, and CBC is a mode of operation that enhances the security of block ciphers.

## Table of Contents
- [About the Project](#about-the-project)
- [How DES-CBC Works](#how-des-cbc-works)
- [Installation](#installation)
- [Usage](#usage)
- [Example](#example)

## About the Project

DES is a symmetric-key algorithm that processes data in blocks of 64 bits using a 56-bit key. The CBC mode, when applied to DES, improves its security by introducing randomness with an initialization vector (IV) and chaining each block's encryption with the previous block's output.

This project is a Python adaptation of the original DES-CBC implementation written in C by tayyipozturk. The C code was refactored into Python while maintaining the core functionality of DES and CBC mode.

## How DES-CBC Works

1. Data Encryption Standard (DES): DES operates on 64-bit blocks of data using a series of permutations, substitutions, and key-based transformations through 16 rounds.

  - Each round uses a different sub-key generated from the main key.
  - The process includes initial permutation, expansion, substitution using S-boxes, and a final permutation to produce the encrypted block.

2. Cipher Block Chaining (CBC) Mode:

  - An Initialization Vector (IV) is used to add randomness to the first block of plaintext before encryption.
  - Each subsequent block is XORed with the previous block's ciphertext before being encrypted.
  - This chaining process ensures that identical plaintext blocks produce different ciphertext blocks, making patterns in the data less detectable.

3. Padding: The plaintext is padded using PKCS#5 padding to ensure that its length is a multiple of 64 bits (8 bytes).

4. Encryption and Decryption:

  - Encryption: Each block is XORed with the previous ciphertext block (or IV for the first block), then encrypted using DES.
  - Decryption: Each block is decrypted using DES, and then XORed with the previous ciphertext block (or IV for the first block) to retrieve the plaintext.

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/DES-CBC-Python.git
cd DES-CBC-Python


## Usage
You can use this script to encrypt and decrypt any plaintext using a custom key.

1. **Running the script**:
    ```bash
    python des_cbc.py

2. **Input: The script will prompt you to enter the following**:

    A key: This is the secret 16-character hexadecimal key used for both encryption and decryption.
    A plaintext: This is the message or data you want to encrypt.

3. **Encryption and Decryption: After entering the key and plaintext, the program will**:

    Encrypt the plaintext using the provided key and IV.
    Show the process of generating the round keys, applying XOR operations, and encryption for each block.
    Decrypt the ciphertext to verify correctness.

## Example
Here's an example of how the program works:
    ```bash
    Enter the key: aabb09182736ccdd
    Enter the plaintext: hello world

    ================================
    DES Encryption and Decryption
    ================================

    --- Process Started ---
    1: Plaintext
    ------------------------------------------------------------
    hello world

    2: Key in Hexadecimal
    ------------------------------------------------------------
    aabb09182736ccdd

    3: Generated Round Keys
    ------------------------------------------------------------
    Round 1: 001110110001011101100101...
    Round 2: 110100101110110011001011...
    ...

    4: Initialization Vector (IV)
    ------------------------------------------------------------
    01100011010010111010100100101101011101010101000110101011...

    ================================
    Encryption Process
    ================================

    Encrypting Block 1:
    ------------------------------------------------------------
    Plaintext Block: 01101000011001010110110001101100...
    XOR with IV: 010011101011110111001101...
    Encrypted Block: 3a94d63fe34c1e05

    Encrypting Block 2:
    ------------------------------------------------------------
    Plaintext Block: 01101100011011110111011101101100...
    XOR with Previous Cipher: 001011010111010001101100...
    Encrypted Block: 9b1f3d0fe72a5689

    Ciphertext: 3a94d63fe34c1e059b1f3d0fe72a5689

    Encryption took 0.12 seconds

    ================================
    Decryption Process
    ================================

    Decrypting Block 1:
    ------------------------------------------------------------
    Ciphertext Block: 3a94d63fe34c1e05
    Decrypted Block: 010011101011110111001101...
    XOR with IV: 01101000011001010110110001101100...

    Decrypting Block 2:
    ------------------------------------------------------------
    Ciphertext Block: 9b1f3d0fe72a5689
    Decrypted Block: 001011010111010001101100...
    XOR with Previous Cipher: 01101100011011110111011101101100...

    Decrypted Plaintext: hello world
    Decryption took 0.14 seconds

    ================================
    Process Completed
    ================================