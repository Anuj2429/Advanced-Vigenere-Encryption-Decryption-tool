from constants import WARN_KEY_MIN_LEN

PRINTABLE_ASCII = set(chr(c) for c in range(32, 127))

def sanitize_key(user_key: str) -> str:
    # Trim leading/trailing spaces, keep internal spaces
    return user_key.strip()

def is_ascii_printable(s: str) -> bool:
    return all(ch in PRINTABLE_ASCII for ch in s)

def needs_short_key_warning(key: str) -> bool:
    return len(key) < WARN_KEY_MIN_LEN

def validate_key_or_raise(key: str) -> None:
    if not key:
        raise ValueError("Please enter a key.")
    if not is_ascii_printable(key):
        raise ValueError("Key contains non-printable characters (ASCII 32–126 only).")
