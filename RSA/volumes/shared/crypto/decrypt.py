from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization

MAX_RSA_PLAINTEXT = 190 # 190 byte limit for RSA OEAP https://crypto.stackexchange.com/a/42100
RSA_CIPHERTEXT_LEN = 256

# Get specified private key
def load_private_key(filename):
    with open(filename, "rb") as key_file:
        return serialization.load_pem_private_key(key_file.read(), password=None)

def split_into_blocks_decrypt(data, private_key):
    decrypted = b''
    for i in range(0, len(data), RSA_CIPHERTEXT_LEN):
        chunk = data[i:i + RSA_CIPHERTEXT_LEN]
        if len(chunk) < RSA_CIPHERTEXT_LEN:
            continue  # skip incomplete block
        decrypted_block = private_key.decrypt(
            chunk,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        decrypted += decrypted_block
    return decrypted