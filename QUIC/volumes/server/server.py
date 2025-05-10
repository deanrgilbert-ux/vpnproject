#!/usr/bin/env python3

import asyncio
import os
import struct
import fcntl
from scapy.all import *
from aioquic.asyncio import serve
from aioquic.quic.configuration import QuicConfiguration
from shared.create_tun import create_tun
from generate_cert import generate_self_signed_cert

# TUN setup
TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_TAP   = 0x0002
IFF_NO_PI = 0x1000
TUN_IP = "192.168.53.98"
SERVER_IP = "10.9.0.11"
QUIC_PORT = 4433


ifname, tun = create_tun(TUNSETIFF, IFF_TUN, IFF_NO_PI)
os.system(f"ip addr add {TUN_IP}/24 dev {ifname}")
os.system(f"ip link set dev {ifname} up")

class VPNServerProtocol:
    def __init__(self, reader, writer):
        self.reader = reader
        self.writer = writer

    async def recv_from_client(self):
        while True:
            data = await self.reader.read(2048)
            if not data:
                print("Client closed connection.")
                os._exit(1)
            pkt = IP(data)
            print(f"From client <==: {pkt.src} --> {pkt.dst}")
            os.write(tun, data)

    def tun_read_cb(self):
        packet = os.read(tun, 2048)
        pkt = IP(packet)
        print(f"From tun ==>: {pkt.src} --> {pkt.dst}")
        self.writer.write(packet)

    async def handle(self):
        loop = asyncio.get_running_loop()
        loop.add_reader(tun, self.tun_read_cb)
        await self.recv_from_client()


def stream_handler(reader, writer):
    asyncio.create_task(VPNServerProtocol(reader, writer).handle())


async def vpn_server():
    generate_self_signed_cert()
    configuration = QuicConfiguration(
        is_client=False,
    )
    configuration.load_cert_chain(certfile="cert.pem", keyfile="key.pem")
    server = await serve(
        host=SERVER_IP,
        port=QUIC_PORT,
        configuration=configuration,
        stream_handler=stream_handler,
    )
    print(f"QUIC VPN server established on IP {SERVER_IP} and port {QUIC_PORT}")
    await asyncio.Future()

if __name__ == "__main__":
    asyncio.run(vpn_server())