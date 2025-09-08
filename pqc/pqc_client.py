import oqs
from time import sleep
from shared import *

# SOCKET TEST
import socket

client_private_key = import_mlkem_pem("pqc/mlkem-client-private.pem")

# Create client and generate keys
client = oqs.KeyEncapsulation(ALGORITHM, client_private_key)

# Get server's public key
server_public_key = import_mlkem_pem("pqc/mlkem-server-public.pem")

# Encapsulate shared secret
encapsulated_key, client_shared_secret = client.encap_secret(server_public_key) # encapsulated_key needs to be transmitted.

# Derive a symmetric key from the shared secret
sym_key = derive_shared_key(client_shared_secret)

# test creating a packet with the encapsulated in it.
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("127.0.0.5", 9001))

server_addr = ("127.0.0.1", 9001)

sock.sendto(encapsulated_key, server_addr)

# Encrypt a message
message = b"This is a test."
ciphertext = aes_encrypt(message, sym_key)

sleep(2)

while True:
    sock.sendto(ciphertext, server_addr)

    #assume handshake has already been completed
    buf = sock.recvfrom(2048)
    if len(buf) > 0:
        print(aes_decrypt(buf[0], sym_key))
        continue
