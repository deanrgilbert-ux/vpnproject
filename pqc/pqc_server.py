import oqs, socket
from shared import *

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('127.0.0.1', 9001))

server_private_key = import_secret_key_pem("pqc/mlkem-server-private.pem")

server = oqs.KeyEncapsulation(ALGORITHM, server_private_key)

sym_key = None
client_addr = None
i = 0

while True:
    # Receive data from socket
    buf = sock.recvfrom(2048)
    if len(buf) > 0: 
        if sym_key == None:
            shared_secret = server.decap_secret(buf[0])
            sym_key = derive_shared_key(shared_secret)
            client_addr = buf[1]
            print(sym_key)

        if buf[1] == client_addr:
            print(aes_decrypt(buf[0], sym_key))
    
    # send an incrememnting value to the client if the 'handshake' has been completed.
    if client_addr is not None:
        sock.sendto(aes_encrypt(i, sym_key), client_addr)

