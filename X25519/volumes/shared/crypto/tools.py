from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import os

AES_KEY_SIZE = 32   # AES-256-GCM
NONCE_SIZE = 12     # GCM nonce 12 * 8 = 96 bits

def load_public_key(filename):
    with open(filename, "rb") as f:
        return serialization.load_pem_public_key(f.read(), backend=default_backend())

def load_private_key(filename):
    with open(filename, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

# Derive AES key from shared secret
def derive_shared_key(private_key, peer_public_key):
    shared_secret = private_key.exchange(peer_public_key)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=None,
        info=b'vpn tunnel',
        backend=default_backend()
    ).derive(shared_secret)