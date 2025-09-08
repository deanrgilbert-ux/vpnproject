import oqs, os, base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

AES_KEY_SIZE = 32
NONCE_SIZE = 12
ALGORITHM = "ML-KEM-1024"

def derive_shared_key(shared_secret: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=None,
        info=b'vpn tunnel',
        backend=default_backend()
    ).derive(shared_secret)

def aes_encrypt(plaintext: bytes, key: bytes) -> bytes:
    nonce = os.urandom(NONCE_SIZE)
    encryptor = Cipher(
        algorithms.AES(key), # AES-256-GCM
        modes.GCM(nonce),
        backend=default_backend()
    ).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return nonce + encryptor.tag + ciphertext

def aes_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    nonce = ciphertext[:NONCE_SIZE]
    tag = ciphertext[NONCE_SIZE:NONCE_SIZE+16]
    ct = ciphertext[NONCE_SIZE+16:]
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce, tag),
        backend=default_backend()
    ).decryptor()
    return decryptor.update(ct) + decryptor.finalize()

def export_secret_key_pem(secret_key: bytes, filename: str):
    encoded_secret_key = base64.b64encode(secret_key).decode("ascii")
    with open(filename, "w+") as file:
        file.write(f"-----BEGIN PRIVATE KEY-----\n{encoded_secret_key}\n-----END PRIVATE KEY-----")

def import_secret_key_pem(filename: str) -> bytes:
    with open(filename, "r") as file:
        pem_content: list[str] = file.read().split("-----")
        if "BEGIN" in pem_content[1] and "END" in pem_content[3]:
            return base64.b64decode(pem_content[2].encode("ascii"))
        else:
            raise ValueError("File is not in valid PEM format.")