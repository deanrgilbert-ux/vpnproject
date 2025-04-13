#!/usr/bin/env python3

import fcntl, struct, os
from scapy.all import *
from shared.create_tun import createTun
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes

### RSA ###
# Get server private key
with open("/keys/server_private.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(key_file.read(), password=None)

MAX_RSA_PLAINTEXT = 190 # 190 byte limit for RSA OEAP https://crypto.stackexchange.com/a/42100
RSA_CIPHERTEXT_LEN = 256

# Create the tun interface
TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_TAP   = 0x0002
IFF_NO_PI = 0x1000
TUN_IP = "192.168.53.98"
ip = "8.8.8.8"

# Create the tun interface
ifname, tun = createTun(TUNSETIFF, IFF_TUN, IFF_NO_PI)

# Set up the tun interface
os.system("ip addr add {}/24 dev {}".format(TUN_IP, ifname))
os.system("ip link set dev {} up".format(ifname))

IP_A = "10.9.0.11"
PORT = 9090

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((IP_A, PORT))

# Set default ip to avoid error
ip = "10.0.0.1"

def split_into_blocks_decrypt(data):
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
    return decrypted.rstrip(b'\x00')

while True:
    # this will block until at least one interface is ready
    ready, _, _ = select.select([sock, tun], [], [])
    for fd in ready:
        if fd is sock:
            data, (ip, port) = sock.recvfrom(2048)
            ### RSA ###
            decrypted_data = split_into_blocks_decrypt(data)
            pkt = IP(decrypted_data)
            print("From socket <==: {} --> {}".format(pkt.src, pkt.dst))
            os.write(tun, decrypted_data)

        if fd is tun:
            packet = os.read(tun, 2048)
            pkt = IP(packet)
            print("From tun ==>: {} --> {}".format(pkt.src, pkt.dst))
            sock.sendto(packet, (ip, port))
