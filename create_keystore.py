import json
import os
from Crypto.Cipher import AES
from Crypto.Hash import keccak
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes

def generate_keystore(private_key: bytes, password: str):
    # Parameters
    salt = get_random_bytes(32)  # Random salt for scrypt
    n = 8192  # scrypt cost factor
    r = 8     # scrypt block size
    p = 1     # scrypt parallelization factor
    dklen = 32  # Desired length of derived key

    # Key derivation using scrypt
    derived_key = scrypt(password.encode(), salt, dklen, N=n, r=r, p=p)

    # Split derived key into encryption and MAC keys
    encryption_key = derived_key[:16]  # First 16 bytes
    mac_key = derived_key[16:]         # Last 16 bytes

    # Encrypt the private key using AES-128-CTR
    iv = get_random_bytes(16)  # Initialization vector
    cipher = AES.new(encryption_key, AES.MODE_CTR, nonce=iv[:8])
    ciphertext = cipher.encrypt(private_key)

    # Compute the MAC (Keccak256 hash)
    mac = keccak.new(digest_bits=256)
    mac.update(mac_key + ciphertext)
    mac_value = mac.hexdigest()

    # Build keystore JSON structure
    keystore = {
        "crypto": {
            "cipher": "aes-128-ctr",
            "cipherparams": {
                "iv": iv.hex(),
            },
            "ciphertext": ciphertext.hex(),
            "kdf": "scrypt",
            "kdfparams": {
                "dklen": dklen,
                "n": n,
                "p": p,
                "r": r,
                "salt": salt.hex(),
            },
            "mac": mac_value,
        },
        "id": os.urandom(16).hex(),  # Random UUID
        "version": 3,
    }

    return keystore


# Example usage
private_key = bytes.fromhex("f7f8c0f8994c7c7285d5b04cbf757ae53558b71edb0a8ad37ca5105690122b5f") 
password = "123456" 

keystore = generate_keystore(private_key, password)

# Save keystore to a file
with open("sample_keystore.json", "w") as f:
    json.dump(keystore, f, indent=4)

print("Keystore generated and saved to keystore.json.")

