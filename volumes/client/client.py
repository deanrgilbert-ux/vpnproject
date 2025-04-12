#!/usr/bin/env python3

import os, socket, struct, fcntl, select
from scapy.all import *
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from shared.create_tun import createTun

MAX_RSA_PLAINTEXT = 190 # 190 byte limit for RSA OEAP https://crypto.stackexchange.com/a/42100
RSA_CIPHERTEXT_LEN = 256

# Load server's public key
with open("/keys/server_public.pem", "rb") as f:
    public_key = serialization.load_pem_public_key(f.read())

# Create the tun interface
TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_TAP   = 0x0002
IFF_NO_PI = 0x1000
ifname, tun = createTun(TUNSETIFF, IFF_TUN, IFF_NO_PI)

os.system("ip addr add 192.168.53.99/24 dev {}".format(ifname))
os.system("ip link set dev {} up".format(ifname))
os.system("ip route add 192.168.60.0/24 dev {}".format(ifname))

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Set a default value for ip to avoid error
ip = "10.0.0.1"

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

while True:
    # this will block until at least one interface is ready
    ready, _, _ = select.select([sock, tun], [], [])
    for fd in ready:
        if fd is sock:
            data, (ip, port) = sock.recvfrom(2048)
            pkt = IP(data)
            print("From socket <==: {} --> {}".format(pkt.src, pkt.dst))
            os.write(tun, data)

        if fd is tun:
            packet = os.read(tun, 2048)
            pkt = IP(packet)
            print("From tun ==>: {} --> {}".format(pkt.src, pkt.dst))
            encrypted_data = split_into_blocks_encrypt(packet)
            sock.sendto(encrypted_data, ("10.9.0.11", 9090))
