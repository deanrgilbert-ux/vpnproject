#!/usr/bin/env python3

import fcntl
import struct
import os
import time
from scapy.all import *
from shared.create_tun import createTun
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes

TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_TAP   = 0x0002
IFF_NO_PI = 0x1000

# Create the tun interface
ifname, tun = createTun(TUNSETIFF, IFF_TUN, IFF_NO_PI)

os.system("ip addr add 192.168.53.99/24 dev {}".format(ifname))
os.system("ip link set dev {} up".format(ifname))

os.system("ip route add 192.168.60.0/24 dev {}".format(ifname))
 
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Set a default value for ip to avoid error
ip = "10.0.0.1"

### RSA ###
# Get server public key
with open("/keys/server_public.pem", "rb") as key_file:
    public_key = serialization.load_pem_public_key(key_file.read())

while True:
    # this will block until at least one interface is ready
    ready, _, _ = select.select([sock, tun], [], [])
    for fd in ready:
        if fd is sock:
            data, (ip, port) = sock.recvfrom(2048)
            pkt = IP(data)
            print("From socket <==: {} --> {}".format(pkt.src, pkt.dst))
            os.write(tun, bytes(pkt))

        if fd is tun:
            packet = os.read(tun, 2048)
            pkt = IP(packet)
            print("From tun ==>: {} --> {}".format(pkt.src, pkt.dst))
            sock.sendto(packet, ("10.9.0.11", 9090))

            ### RSA ###
            # 190 byte limit for RSA OEAP https://crypto.stackexchange.com/a/42100
            encrypted_data = public_key.encrypt(
                packet[:190],
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            sock.sendto(encrypted_data, ("10.9.0.11", 9090))

