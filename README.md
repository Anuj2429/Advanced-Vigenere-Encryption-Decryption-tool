# Advanced Vigenère Cipher (Tkinter)

A Tkinter desktop app that keeps the "per-byte Vigenère-style" feel while adding modern safeguards:

- PBKDF2 key derivation (SHA-256, 200k iterations)
- Random per-encryption salt (16 bytes)
- Deterministic keystream expansion for messages longer than the key
- Multi-pass transform: Add -> XOR -> Sub (and reversed on decrypt)
- Text Mode (scrollable input/output) and File Mode (binary-safe read/write)
- Short-key popup warning (< 8 chars), password-style key box with Show/Copy, and Generate Key (for encryption)

## Run

```bash
python app.py
```

No external dependencies required (Tkinter is included with most Python installs).
