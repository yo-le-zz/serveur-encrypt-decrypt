# serveur-encrypt-decrypt

This repository contains scripts to **encrypt and decrypt data via a server**, as well as an admin tool to prepare encrypted files.

---

## 🔹 Contents

- `get_data.py`: Client script to communicate with the server and **encrypt/decrypt** files or content.
- `cipher.py`: **Admin script** to prepare secure `.bin` files from JSON files. **Do not send this to clients.**

---

## ⚙️ Configuration

### 1. get_data.py

Before using it, fill in:

```python
SERVER_URL = "YOUR_NGROK_LINK"  # Your server URL
HMAC_SECRET = b"YOUR_HMAC_KEY"   # Shared HMAC key with the server
license.txt will be created automatically to store the license.

machine_id.txt will be created automatically to identify the machine.

2. cipher.py
Before using it, define the server key:

python
Copier le code
key = b"KEY_OF_YOUR_SERVER"
📝 Usage
1. Client Encryption / Decryption (get_data.py)
python
Copier le code
from get_data import encrypt, decrypt

# Encrypt a file
encrypted = encrypt(
    source_type="file",
    data="secure.json",
    is_binary=True,
    bits=True
)

# Decrypt a file
decrypted = decrypt(
    source_type="file",
    data="secure.bin",
    is_binary=True,
    bits=True
)
Options:

source_type: "file" or "content".

bits: if True, data is converted to bit representation.

2. Prepare secure files (admin, cipher.py)
bash
Copier le code
python cipher.py input.json output.bin
input.json: plaintext JSON file to encrypt.

output.bin: generated encrypted file.

⚠️ cipher.py must never be shared with clients.

🛠 Features
Conversion bits ↔ bytes.

Automatic machine ID generation and license handling.

Secure server communication via HMAC + timestamp.

Simple API: encrypt(...) and decrypt(...).

🔒 Security
Keep the server key secret at all times.

Clients must never have access to cipher.py or the server key.

📦 Dependencies
Python 3.8+

requests

cryptography

bash
Copier le code
pip install requests cryptography
📌 Notes
.bin files are generated in binary format and can be converted to bits for certain operations.

Server errors return explicit messages.

yaml
Copier le code

---

## Steps to Set Up on a Server

1. **Install Python and dependencies**

```bash
sudo apt update
sudo apt install python3 python3-pip -y
pip install requests cryptography flask
Prepare your server script

You need a small server (Flask example) that accepts JSON requests and handles encryption/decryption using the server key.

Example server.py:

python
Copier le code
from flask import Flask, request, jsonify
from cryptography.fernet import Fernet
import hmac, hashlib
import datetime

app = Flask(__name__)
SERVER_KEY = b"KEY_OF_YOUR_SERVER"

def verify_signature(machine_id, timestamp, signature, secret):
    msg = f"{machine_id}:{timestamp}".encode()
    expected = hmac.new(secret, msg, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)

@app.route("/", methods=["POST"])
def process():
    data = request.json
    if not verify_signature(data["machine_id"], data["timestamp"], data["signature"], SERVER_KEY):
        return jsonify({"error": "Invalid signature"}), 403
    
    fernet = Fernet(SERVER_KEY)
    if data["action"] == "encrypt":
        ct = fernet.encrypt(data["plaintext"].encode("latin1"))
        return jsonify({"ciphertext": ct.decode("latin1")})
    elif data["action"] == "decrypt":
        pt = fernet.decrypt(data["ciphertext"].encode("latin1"))
        return jsonify({"decrypted": pt.decode("latin1")})
    else:
        return jsonify({"error": "Invalid action"}), 400

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
Run the server

bash
Copier le code
python3 server.py
Expose server if needed

Use Ngrok or configure firewall/NAT to allow client access:

bash
Copier le code
ngrok http 5000
Take the generated Ngrok URL and put it in get_data.py as SERVER_URL.

Client usage

On the client side, get_data.py can now encrypt/decrypt files using the server.

If you want, I can also make a full ready-to-deploy folder structure for the server and client with scripts, licenses, and example files, so you can just push to GitHub and it works.
