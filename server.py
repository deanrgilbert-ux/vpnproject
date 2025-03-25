import os
import threading
from utils import setup_tun, create_udp_socket, send_packet, receive_packet

# Server config
UDP_IP = "0.0.0.0"
CLIENT_IP = "localhost"

def handle_client(sock, tun):
    """Reads from client and writes to tun"""
    while True:
        data, _ = receive_packet(sock)
        os.write(tun, data)

def vpn_server():
    sock = create_udp_socket(UDP_IP)
    tun = setup_tun("10.111.0.1")

    # Start the listener in separate thread
    threading.Thread(target=handle_client, args=(sock, tun)).start()

    while True:
        packet = os.read(tun, 2048)
        send_packet(sock, packet, CLIENT_IP)

if __name__ == "__main__":
    vpn_server()
