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

# Create client and generate keys
client = oqs.KeyEncapsulation(ALGORITHM)
client_public_key = client.generate_keypair()
client_secret_key = client.export_secret_key()

export_secret_key_pem(client_secret_key, "mlkem-client-private.pem")

# Test loading keys after they've been exported
client_loaded = oqs.KeyEncapsulation(ALGORITHM, client_secret_key)

# Create server and generate keys
server = oqs.KeyEncapsulation(ALGORITHM)
server_public_key = server.generate_keypair()
server_private_key = server.export_secret_key()

export_secret_key_pem(server_private_key, "mlkem-server-private.pem")

# Encapsulate shared secret
encapsulated_key, client_shared_secret = client_loaded.encap_secret(server_public_key) # encapsulated_key needs to be transmitted.

# Decapsulate shared secret
server_shared_secret = server.decap_secret(encapsulated_key) # one party stores symmetric key, the other decapsulates it using this.

# Derive a symmetric key from the shared secret
client_sym_key = derive_shared_key(client_shared_secret)
server_sym_key = derive_shared_key(server_shared_secret)

# Encrypt a message
message = b"This is a test."
ciphertext = aes_encrypt(message, client_sym_key)

# Print the decrypted message.
print(aes_decrypt(ciphertext, server_sym_key))