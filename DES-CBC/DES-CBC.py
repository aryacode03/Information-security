import random
import time

BLOCK_SIZE = 64

# Permutation Tables
IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]

FP = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
]

SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

E = [
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1
]

P = [
    16, 7, 20, 21, 29, 12, 28, 17,
    1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9,
    19, 13, 30, 6, 22, 11, 4, 25
]

PC1 = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4
]

PC2 = [
    14, 17, 11, 24, 1, 5, 3, 28,
    15, 6, 21, 10, 23, 19, 12, 4,
    26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40,
    51, 45, 33, 48, 44, 49, 39, 56,
    34, 53, 46, 42, 50, 36, 29, 32
]

S = [
    [
        0xe, 0x4, 0xd, 0x1, 0x2, 0xf, 0xb, 0x8, 0x3, 0xa, 0x6, 0xc, 0x5, 0x9, 0x0, 0x7,
        0x0, 0xf, 0x7, 0x4, 0xe, 0x2, 0xd, 0x1, 0xa, 0x6, 0xc, 0xb, 0x9, 0x5, 0x3, 0x8,
        0x4, 0x1, 0xe, 0x8, 0xd, 0x6, 0x2, 0xb, 0xf, 0xc, 0x9, 0x7, 0x3, 0xa, 0x5, 0x0,
        0xf, 0xc, 0x8, 0x2, 0x4, 0x9, 0x1, 0x7, 0x5, 0xb, 0x3, 0xe, 0xa, 0x0, 0x6, 0xd
    ],
    [
        0xf, 0x1, 0x8, 0xe, 0x6, 0xb, 0x3, 0x4, 0x9, 0x7, 0x2, 0xd, 0xc, 0x0, 0x5, 0xa,
        0x3, 0xd, 0x4, 0x7, 0xf, 0x2, 0x8, 0xe, 0xc, 0x0, 0x1, 0xa, 0x6, 0x9, 0xb, 0x5,
        0x0, 0xe, 0x7, 0xb, 0xa, 0x4, 0xd, 0x1, 0x5, 0x8, 0xc, 0x6, 0x9, 0x3, 0x2, 0xf,
        0xd, 0x8, 0xa, 0x1, 0x3, 0xf, 0x4, 0x2, 0xb, 0x6, 0x7, 0xc, 0x0, 0x5, 0xe, 0x9
    ],
    [
        0xa ,0x0 ,0x9 ,0xe ,0x6 ,0x3 ,0xf ,0x5 ,0x1 ,0xd ,0xc ,0x7 ,0xb ,0x4 ,0x2 ,0x8,
        0xd ,0x7 ,0x0 ,0x9 ,0x3 ,0x4 ,0x6 ,0xa ,0x2 ,0x8 ,0x5 ,0xe ,0xc ,0xb ,0xf ,0x1,
        0xd ,0x6 ,0x4 ,0x9 ,0x8 ,0xf ,0x3 ,0x0 ,0xb ,0x1 ,0x2 ,0xc ,0x5 ,0xa ,0xe ,0x7,
        0x1 ,0xa ,0xd ,0x0 ,0x6 ,0x9 ,0x8 ,0x7 ,0x4 ,0xf ,0xe ,0x3 ,0xb ,0x5 ,0x2 ,0xc
    ],
    [
        0x7 ,0xd ,0xe, 0x3 ,0x0 ,0x6 ,0x9 ,0xa ,0x1 ,0x2 ,0x8 ,0x5 ,0xb ,0xc ,0x4 ,0xf,
        0xd ,0x8 ,0xb ,0x5 ,0x6 ,0xf ,0x0 ,0x3 ,0x4 ,0x7 ,0x2 ,0xc ,0x1 ,0xa ,0xe ,0x9,
        0xa ,0x6 ,0x9 ,0x0 ,0xc ,0xb ,0x7 ,0xd ,0xf ,0x1 ,0x3 ,0xe ,0x5 ,0x2 ,0x8 ,0x4,
        0x3 ,0xf ,0x0 ,0x6 ,0xa ,0x1 ,0xd ,0x8 ,0x9 ,0x4 ,0x5 ,0xb ,0xc ,0x7 ,0x2 ,0xe
    ],
    [   0x2 ,0xc ,0x4 ,0x1 ,0x7 ,0xa ,0xb ,0x6 ,0x8 ,0x5 ,0x3 ,0xf ,0xd ,0x0 ,0xe ,0x9,
        0xe ,0xb ,0x2 ,0xc ,0x4 ,0x7 ,0xd ,0x1 ,0x5 ,0x0 ,0xf ,0xa ,0x3 ,0x9 ,0x8 ,0x6,
        0x4 ,0x2 ,0x1 ,0xb ,0xa ,0xd ,0x7 ,0x8 ,0xf ,0x9 ,0xc ,0x5 ,0x6 ,0x3 ,0x0 ,0xe,
        0xb ,0x8 ,0xc ,0x7 ,0x1 ,0xe ,0x2 ,0xd ,0x6 ,0xf ,0x0 ,0x9 ,0xa ,0x4 ,0x5 ,0x3
    ], 
    [
        0xc ,0x1 ,0xa ,0xf ,0x9 ,0x2 ,0x6 ,0x8 ,0x0 ,0xd ,0x3 ,0x4 ,0xe ,0x7 ,0x5 ,0xb,
        0xa ,0xf ,0x4 ,0x2 ,0x7 ,0xc ,0x9 ,0x5 ,0x6 ,0x1 ,0xd ,0xe ,0x0 ,0xb ,0x3 ,0x8,
        0x9 ,0xe ,0xf ,0x5 ,0x2 ,0x8 ,0xc ,0x3 ,0x7 ,0x0 ,0x4 ,0xa ,0x1 ,0xd ,0xb ,0x6,
        0x4 ,0x3 ,0x2 ,0xc ,0x9 ,0x5 ,0xf ,0xa ,0xb ,0xe ,0x1 ,0x7 ,0x6 ,0x0 ,0x8 ,0xd
    ],
    [   
        0x4, 0xb, 0x2, 0xe, 0xf, 0x0, 0x8, 0xd, 0x3, 0xc, 0x9, 0x7, 0x5, 0xa, 0x6, 0x1,
        0xd, 0x0, 0xb, 0x7, 0x4, 0x9, 0x1, 0xa, 0xe, 0x3, 0x5, 0xc, 0x2, 0xf, 0x8, 0x6,
        0x1, 0x4, 0xb, 0xd, 0xc, 0x3, 0x7, 0xe, 0xa, 0xf, 0x6, 0x8, 0x0, 0x5, 0x9, 0x2,
        0x6, 0xb, 0xd, 0x8, 0x1, 0x4, 0xa, 0x7, 0x9, 0x5, 0x0, 0xf, 0xe, 0x2, 0x3, 0xc
    ],          
    [   
        0xd, 0x2, 0x8, 0x4, 0x6, 0xf, 0xb, 0x1, 0xa, 0x9, 0x3, 0xe, 0x5, 0x0, 0xc, 0x7,
        0x1, 0xf, 0xd, 0x8, 0xa, 0x3, 0x7, 0x4, 0xc, 0x5, 0x6, 0xb, 0x0, 0xe, 0x9, 0x2,
        0x7, 0xb, 0x4, 0x1, 0x9,0xc, 0xe, 0x2, 0x0, 0x6, 0xa, 0xd, 0xf, 0x3, 0x5, 0x8,
        0x2, 0x1, 0xe, 0x7, 0x4, 0xa, 0x8, 0xd, 0xf, 0xc, 0x9, 0x0, 0x3, 0x5, 0x6, 0xb
    ]
]

# Mengubah biner menjadi desimal
def binary_to_decimal(binary):
    return int(binary, 2)

# Mengubah string menjadi format hex
def string_to_hex(s):
    return ''.join('{:02x}'.format(ord(c)) for c in s)

# Mengubah hex menjadi format biner
def hex_to_binary(hex_string):
    hex_bin_map = {
        '0': '0000', '1': '0001', '2': '0010', '3': '0011',
        '4': '0100', '5': '0101', '6': '0110', '7': '0111',
        '8': '1000', '9': '1001', 'a': '1010', 'b': '1011',
        'c': '1100', 'd': '1101', 'e': '1110', 'f': '1111'
    }
    return ''.join(hex_bin_map[c] for c in hex_string)

# Mengubah biner menjadi hex
def binary_to_hex(binary_string):
    return ''.join('{:x}'.format(int(binary_string[i:i + 4], 2)) for i in range(0, len(binary_string), 4))

# Fungsi untuk melakukan pergeseran kiri
def shift_left(s, n):
    shifted = s[n:] + s[:n]
    print(f"Shifted {n} bits: {shifted}")
    return shifted

# Fungsi XOR untuk dua string biner
def xor_strings(str1, str2):
    result = ''.join(['0' if str1[i] == str2[i] else '1' for i in range(len(str1))])
    print(f"XOR result: {result}")
    return result

# Fungsi untuk melakukan permutasi berdasarkan tabel
def permute_key(key, perm_table):
    return ''.join([key[perm_table[i] - 1] for i in range(len(perm_table))])

# Membuat kunci untuk tiap ronde
def generate_round_keys(key):
    round_keys = []
    permuted_key = permute_key(key, PC1)
    left_half, right_half = permuted_key[:28], permuted_key[28:]
    
    for round in range(16):
        left_half = shift_left(left_half, SHIFTS[round])
        right_half = shift_left(right_half, SHIFTS[round])
        merged_key = left_half + right_half
        round_key = permute_key(merged_key, PC2)
        round_keys.append(round_key)
        print(f"Round {round + 1} key: {round_key}")
    
    return round_keys

# Membuat vektor inisialisasi acak
def generate_random_initialization_vector():
    iv = ''.join([str(random.randint(0, 1)) for _ in range(64)])
    print(f"Initialization Vector (IV): {iv}")
    return iv

# Fungsi padding PKCS5
def padding(plain_text):
    padding_len = 8 - (len(plain_text) % 8)
    padded_text = plain_text + chr(padding_len) * padding_len
    print(f"Padded plain text: {padded_text}")
    return padded_text

# Fungsi untuk menghilangkan padding PKCS5
def remove_padding(plain_text):
    padding_len = ord(plain_text[-1])
    return plain_text[:-padding_len]

# Membagi plain text menjadi blok-blok
def divide_plain_text_to_blocks(plain_text):
    return [plain_text[i:i + 64] for i in range(0, len(plain_text), 64)]

# Fungsi DES utama
def DES(plain_text, round_keys):
    initial_permutation = permute_key(plain_text, IP)
    left_half, right_half = initial_permutation[:32], initial_permutation[32:]
    
    for i in range(16):
        expanded_right = permute_key(right_half, E)
        xor_result = xor_strings(expanded_right, round_keys[i])
        
        sbox_output = ''
        for j in range(8):
            row = binary_to_decimal(xor_result[j * 6] + xor_result[j * 6 + 5])
            col = binary_to_decimal(xor_result[j * 6 + 1:j * 6 + 5])
            sbox_val = S[j][16 * row + col]
            sbox_output += '{:04b}'.format(sbox_val)
        
        permuted_sbox_output = permute_key(sbox_output, P)
        xor_result = xor_strings(left_half, permuted_sbox_output)
        
        if i != 15:
            left_half = right_half
            right_half = xor_result
        else:
            left_half = xor_result
        
        print(f"Round {i + 1}: L = {left_half}, R = {right_half}")
    
    merged = left_half + right_half
    return permute_key(merged, FP)

# Fungsi CBC mode
def CBC(blocks, iv, round_keys, mode):
    cipher_blocks = []
    previous_block = iv
    
    for index, block in enumerate(blocks):
        print(f"\n{'Encrypting' if mode == 0 else 'Decrypting'} Block {index + 1}:")
        if mode == 0:  # Encrypt
            xor_result = xor_strings(block, previous_block)
            cipher_text = DES(xor_result, round_keys)
            cipher_blocks.append(cipher_text)
            previous_block = cipher_text
        else:  # Decrypt
            before_xor = DES(block, round_keys)
            plain_text = xor_strings(before_xor, previous_block)
            cipher_blocks.append(plain_text)
            previous_block = block
    
    return cipher_blocks

# Fungsi enkripsi
def encrypt(plain_text, iv, round_keys):
    plain_text = padding(plain_text)
    binary_plain_text = hex_to_binary(string_to_hex(plain_text))
    plain_blocks = divide_plain_text_to_blocks(binary_plain_text)
    
    encrypted_blocks = CBC(plain_blocks, iv, round_keys, 0)
    cipher_text = ''.join([binary_to_hex(block) for block in encrypted_blocks])
    print(f"Cipher text: {cipher_text}")
    return encrypted_blocks

# Fungsi dekripsi
def decrypt(encrypted_blocks, iv, round_keys):
    reversed_round_keys = round_keys[::-1]
    decrypted_blocks = CBC(encrypted_blocks, iv, reversed_round_keys, 1)
    
    decrypted_hex = ''.join([binary_to_hex(block) for block in decrypted_blocks])
    decrypted_text = bytes.fromhex(decrypted_hex).decode('utf-8', errors='ignore')
    return remove_padding(decrypted_text)

# Fungsi untuk membuat output lebih rapi
def print_banner(message):
    print("\n" + "=" * 60)
    print(f"{message:^60}")
    print("=" * 60 + "\n")

def print_step(step, description, value):
    print(f"{step}: {description}")
    print(f"{'-' * 60}")
    print(f"{value}\n")

# Main function
if __name__ == "__main__":
    # Meminta input dari pengguna untuk plaintext
    print_banner("DES Encryption and Decryption")
    while True:
        str_input = input("Masukkan teks yang akan dienkripsi (1-64 karakter): ").strip()
        if 1 <= len(str_input) <= 64:
            break
        else:
            print("Input tidak valid. Pastikan panjang teks antara 1 hingga 64 karakter.")

    # Meminta input dari pengguna untuk kunci
    while True:
        key = input("Masukkan kunci enkripsi (16 karakter hexadecimal): ").strip().lower()
        if len(key) == 16 and all(c in "0123456789abcdef" for c in key):
            break
        else:
            print("Input tidak valid. Pastikan kunci terdiri dari 16 karakter hexadecimal (0-9, a-f).")

    # Proses enkripsi dan dekripsi
    print_banner("Process Started")
    start = time.time()
    binary_key = hex_to_binary(key)
    plain_text = str_input
    
    print_step("1", "Plaintext", plain_text)
    print_step("2", "Key in Hexadecimal", key)

    round_keys = generate_round_keys(binary_key)
    IV = generate_random_initialization_vector()

    print_step("3", "Generated Round Keys", "\n".join([f"Round {i+1}: {rk}" for i, rk in enumerate(round_keys)]))
    print_step("4", "Initialization Vector (IV)", IV)

    print_banner("Encryption Process")
    encrypted_blocks = encrypt(plain_text, IV, round_keys)
    print(f"Encryption took {time.time() - start:.2f} seconds")

    print_banner("Decryption Process")
    start = time.time()
    decrypted_text = decrypt(encrypted_blocks, IV, round_keys)
    print_step("5", "Decrypted Text", decrypted_text)
    print(f"Decryption took {time.time() - start:.2f} seconds")
    print_banner("Process Completed")