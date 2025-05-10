#!/usr/bin/env python3

import asyncio
import os
import struct
import fcntl
from scapy.all import *
from aioquic.asyncio import connect
from aioquic.quic.configuration import QuicConfiguration
from shared.create_tun import create_tun

# TUN setup
TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_TAP   = 0x0002
IFF_NO_PI = 0x1000

ifname, tun = create_tun(TUNSETIFF, IFF_TUN, IFF_NO_PI)
os.system(f"ip addr add 192.168.53.99/24 dev {ifname}")
os.system(f"ip link set dev {ifname} up")
os.system(f"ip route add 192.168.60.0/24 dev {ifname}")

async def recv_from_server(reader):
    while True:
        data = await reader.read(2048)
        if not data:
            print("Server closed connection.")
            os._exit(1)
        pkt = IP(data)
        print(f"From server <==: {pkt.src} --> {pkt.dst}")
        os.write(tun, data)

def tun_read_cb(writer):
    packet = os.read(tun, 2048)
    pkt = IP(packet)
    print(f"From tun ==>: {pkt.src} --> {pkt.dst}")
    writer.write(packet)

async def vpn_client():
    configuration = QuicConfiguration(
        is_client=True,
        verify_mode=False
    )

    async with connect("10.9.0.11", 4433, configuration=configuration) as connection:
        # quic = connection._quic
        # stream_id = quic.get_next_available_stream_id()
        reader, writer = await connection.create_stream()

        loop = asyncio.get_running_loop()
        loop.add_reader(tun, tun_read_cb, writer)

        await recv_from_server(reader)  # Keep reading server

if __name__ == "__main__":
    asyncio.run(vpn_client())