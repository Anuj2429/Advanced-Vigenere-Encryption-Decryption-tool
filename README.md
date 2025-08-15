# Advanced-Vigenere-Encryption-Decryption-tool
A modern and secure reimagining of the classic Vigenère cipher, implemented in Python with a sleek dark-themed Tkinter interface.This project goes beyond the historical cipher by adding key strengthening, per-message salting, and binary-safe encryption—making it suitable for encrypting everything from source code to images.

🚀 Features
🔑 Stronger Key Handling
   Accepts short user keys (1–2 characters) but warns about low security.
   Uses PBKDF2 (SHA-256) with 200,000 iterations for secure key derivation.
   Random strong key generator included.
   No keys stored — copy key option provided.

🛡️ Per-Message Random Salt
    Every encryption generates a new 16-byte salt.
    Salt is packaged with ciphertext for secure decryption.
    Prevents precomputed/rainbow table attacks.

🔄 Multi-Pass Binary-Safe Encryption
   Works on raw bytes (supports any file format).
   Three transformations per byte:
   Add key byte (mod 256)
   XOR with next key byte
   Subtract key byte (mod 256)
   Keystream repeats for longer data.

📂 Flexible Input/Output
   Text Mode: Scrollable text area for encryption/decryption.
   File Mode: Encrypt/decrypt any file and choose save location.
   Works seamlessly with programs, documents, and images.

🔒 Security Advantages
    Protects against frequency analysis (improved over original Vigenère).
    Salt + PBKDF2 make brute-force impractical.
    Binary-safe, preserving all file formats without corruption.

📦 Requirements
   Python 3.6+
   Tkinter (comes pre-installed with Python)

⚡ How to Run
    python app.py
