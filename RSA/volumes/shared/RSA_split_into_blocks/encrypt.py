from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes

MAX_RSA_PLAINTEXT = 190 # 190 byte limit for RSA OEAP https://crypto.stackexchange.com/a/42100
RSA_CIPHERTEXT_LEN = 256

# Load server's public key
with open("/keys/server_public.pem", "rb") as f:
    public_key = serialization.load_pem_public_key(f.read())

def split_into_blocks_encrypt(packet_bytes):
    blocks = []
    for i in range(0, len(packet_bytes), MAX_RSA_PLAINTEXT):
        chunk = packet_bytes[i:i + MAX_RSA_PLAINTEXT]
        if len(chunk) < MAX_RSA_PLAINTEXT:
            chunk += b'\x00' * (MAX_RSA_PLAINTEXT - len(chunk))
        encrypted = public_key.encrypt(
            chunk,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        blocks.append(encrypted)
    return b''.join(blocks)