# RC4 Encryption and Decryption in Python

This is a Python implementation of the **RC4 stream cipher** algorithm, adapted from a PHP implementation. RC4 is a simple, fast, and widely-used encryption algorithm that processes data byte-by-byte. This implementation allows for both **encryption** and **decryption** of plaintext using a key provided by the user.

## Table of Contents
- [About the Project](#about-the-project)
- [How RC4 Works](#how-rc4-works)
- [Installation](#installation)
- [Usage](#usage)
- [Example](#example)

## About the Project

RC4 is a stream cipher, meaning it processes plaintext by generating a pseudo-random stream of bits (or bytes) called the keystream, and XORs it with the plaintext to produce ciphertext. Decryption is simply done by XORing the ciphertext with the same keystream to retrieve the original plaintext.

This project is a **Python adaptation** of the original RC4 implementation written in PHP by [agung96tm](https://github.com/agung96tm/rc4). The PHP code was refactored into Python while maintaining the core functionality of the RC4 algorithm.

## How RC4 Works

1. **Key Scheduling Algorithm (KSA)**: The algorithm initializes a state array `S` of size 256, which is then shuffled based on the key provided by the user. This generates a permutation of all 256 possible bytes.
   
2. **Pseudo-Random Generation Algorithm (PRGA)**: Once the state `S` is initialized, the PRGA generates the keystream byte by byte. Each byte from the keystream is XORed with a corresponding byte of the plaintext to generate the ciphertext.

3. **XOR Process**: In both encryption and decryption, the keystream is XORed with the input (plaintext or ciphertext). Because of the properties of XOR, applying it twice with the same keystream retrieves the original data.

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/rc4-encryption-python.git

## Usage
You can use this script to encrypt and decrypt any plaintext using a custom key.

1. **Running the script**:
    ```bash
    rc4.py

2. **Input: The script will prompt you to enter the following**:

    A key: This is the secret key used for both encryption and decryption.
    A plaintext: This is the message or data you want to encrypt.

3. **Encryption and Decryption: After entering the key and plaintext, the program will**:

    Encrypt the plaintext using the provided key.
    Show the process of generating the keystream and applying XOR operations.
    Decrypt the ciphertext to verify correctness.

## Example
Here's an example of how the program works:

    ```bash
    Enter the key: secretkey
    Enter the plaintext: hello world

    --- Initializing S-box ---
      i: 0, Key char: 's' (ord: 115), j: 115
      i: 1, Key char: 'e' (ord: 101), j: 217
      ...

    --- Starting Encryption ---
    laintext: hello world

    --- Generating Stream Key and XOR Process ---

    Step 1:
      i: 1, j: 217, S[i]: 137, S[j]: 86
      Stream key byte: 115 (from S[t]: S[115])
      Char 'h' (ord: 104) XOR with stream key 115 = 27 (chr: \x1b)
    ...

    Encrypted Ciphertext: \x1b\x0e\x03\x07\x00,\x04\x1f\x06\x12

    --- Starting Decryption ---
    Ciphertext: \x1b\x0e\x03\x07\x00,\x04\x1f\x06\x12

    Decrypted Plaintext: hello world