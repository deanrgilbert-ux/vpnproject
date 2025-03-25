import os
from utils import setup_tun, create_udp_socket, send_packet, receive_packet

# Client config
SERVER_IP = "localhost"

def vpn_client():
    sock = create_udp_socket()
    tun = setup_tun("10.111.0.2")

    while True:
        packet = os.read(tun, 2048)
        send_packet(sock, packet, SERVER_IP)

        data, _ = receive_packet(sock)
        os.write(tun, data)


if __name__ == "__main__":
    vpn_client()
