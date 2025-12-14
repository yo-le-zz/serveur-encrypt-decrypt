# The cipher script is not to be sent to the client; it's an admin script that takes the data from secure.json, 
# encrypts it with the same key as the server, and then converts it to binary. Usage: python cipher.py input.json output.bin
from cryptography.fernet import Fernet
import sys
import os

# =========================
# CONFIG
# =========================

key = b"KEY_OF_YOUR_SERVEUR"

if len(sys.argv) != 3:
    print("Usage : python cipher.py input.json output.bin")
    sys.exit(1)

not_secure_path = sys.argv[1]
secure_path = sys.argv[2]

if not not_secure_path.endswith(".json"):
    raise ValueError("Le fichier d'entrée doit être un .json")

if not secure_path.endswith(".bin"):
    raise ValueError("Le fichier de sortie doit être un .bin")


# =========================
# FUNCTIONS
# =========================

def encrypt_data(data: bytes, key: bytes) -> bytes:
    fernet = Fernet(key)
    return fernet.encrypt(data)


def bytes_to_bits_string(data: bytes) -> bytes:
    bits = ''.join(format(b, '08b') for b in data)
    return bits.encode("ascii")


# =========================
# MAIN
# =========================

if __name__ == "__main__":

    # ✅ LECTURE EN BINAIRE
    with open(not_secure_path, "rb") as f:
        plaintext = f.read()   # bytes ✔

    ciphertext = encrypt_data(plaintext, key)
    bits = bytes_to_bits_string(ciphertext)

    # ✅ ÉCRITURE EN BINAIRE
    with open(secure_path, "wb") as f:
        f.write(bits)

    print(f"✔ Fichier chiffré écrit dans : {secure_path}")
