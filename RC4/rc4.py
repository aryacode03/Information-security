class RC4:
    def __init__(self, key):
        self.key = key
        self.s = []

    def encrypt(self, plaintext):
        self.plaintext = plaintext
        self._initialize_sbox()
        
        print("\n--- Starting Encryption ---")
        print(f"Plaintext: {plaintext}")
        self.ciphertext = self._pseudo_random_with_xor(plaintext)
        print(f"Encrypted Ciphertext: {self.ciphertext}\n")
        return self.ciphertext

    def decrypt(self, ciphertext):
        self.ciphertext = ciphertext
        self._initialize_sbox()
        
        print("\n--- Starting Decryption ---")
        print(f"Ciphertext: {ciphertext}")
        self.plaintext = self._pseudo_random_with_xor(ciphertext)
        print(f"Decrypted Plaintext: {self.plaintext}\n")
        return self.plaintext

    def _pseudo_random_with_xor(self, data):
        n = len(data)
        i = j = 0
        data = list(data)

        print("\n--- Generating Stream Key and XOR Process ---")
        for m in range(n):
            i = (i + 1) % 256
            j = (j + self.s[i]) % 256

            # Swap values in S-box
            self._swap(i, j)

            t = (self.s[i] + self.s[j]) % 256
            stream_key_byte = self.s[t]
            char = ord(data[m])
            xor_result = stream_key_byte ^ char

            # Show detailed process for each step
            print(f"\nStep {m + 1}:")
            print(f"  i: {i}, j: {j}, S[i]: {self.s[i]}, S[j]: {self.s[j]}")
            print(f"  Stream key byte: {stream_key_byte} (from S[t]: S[{t}])")
            print(f"  Char '{data[m]}' (ord: {char}) XOR with stream key {stream_key_byte} = {xor_result} (chr: {chr(xor_result)})")

            # Apply XOR to the character
            data[m] = chr(xor_result)

        return ''.join(data)

    def _initialize_sbox(self):
        self.s = list(range(256))
        j = 0
        n = len(self.key)

        print("\n--- Initializing S-box ---")
        for i in range(256):
            char = ord(self.key[i % n])
            j = (j + self.s[i] + char) % 256
            self._swap(i, j)
            
            # Show S-box initialization process
            if i < 10:  # Show first 10 steps for clarity
                print(f"  i: {i}, Key char: '{self.key[i % n]}' (ord: {char}), j: {j}")
                print(f"  S[{i}]: {self.s[i]}, S[{j}]: {self.s[j]}")

    def _swap(self, i, j):
        self.s[i], self.s[j] = self.s[j], self.s[i]

# Main code for user input
if __name__ == "__main__":
    key = input("Enter the key: ")
    plaintext = input("Enter the plaintext: ")

    # Create RC4 instance
    rc4 = RC4(key)

    # Encrypt plaintext
    encrypted_text = rc4.encrypt(plaintext)

    # Decrypt the ciphertext to verify correctness
    decrypted_text = rc4.decrypt(encrypted_text)
