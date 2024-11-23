import json
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Hash import keccak
import binascii

# Load keystore
with open("redguild1.json", "r") as f:
# with open("sample_keystore.json", "r") as f:
    keystore = json.load(f)

password = "123456"  # Known password
crypto = keystore["crypto"]
kdfparams = crypto["kdfparams"]

# Derive the key using scrypt
derived_key = scrypt(
    password.encode(),
    binascii.unhexlify(kdfparams["salt"]),
    kdfparams["dklen"],
    N=kdfparams["n"],
    r=kdfparams["r"],
    p=kdfparams["p"],
)

# Verify MAC
ciphertext = binascii.unhexlify(crypto["ciphertext"])
mac_key = derived_key[16:]
mac = keccak.new(digest_bits=256)
mac.update(mac_key + ciphertext)
computed_mac = mac.hexdigest()

if computed_mac != crypto["mac"]:
    print("Password is incorrect or MAC mismatch")
    exit()

# Decrypt ciphertext
iv = binascii.unhexlify(crypto["cipherparams"]["iv"])
cipher = AES.new(derived_key[:16], AES.MODE_CTR, nonce=iv[:8])  # Use the first 8 bytes of IV as nonce
private_key = cipher.decrypt(ciphertext)
print("Private Key:", binascii.hexlify(private_key).decode())
