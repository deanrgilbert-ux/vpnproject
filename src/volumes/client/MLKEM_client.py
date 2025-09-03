from scapy.all import *
from shared.create_tun import create_tun
from shared.crypto.encrypt import encrypt
from shared.crypto.decrypt import decrypt
from shared.crypto.tools import load_public_key
from shared.crypto.tools import load_private_key

# Logging setup
logging.basicConfig(
    filename='/volumes/MLKEM_client.log',
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)

# Create the tun interface
TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_TAP   = 0x0002
IFF_NO_PI = 0x1000
ifname, tun = create_tun(TUNSETIFF, IFF_TUN, IFF_NO_PI)

os.system("ip addr add 192.168.53.99/24 dev {}".format(ifname))
os.system("ip link set dev {} up".format(ifname))
os.system("ip route add 192.168.60.0/24 dev {}".format(ifname))

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Generate a keypair.

while True:
    # this will block until at least one interface is ready
    ready, _, _ = select.select([sock, tun], [], [])
    for fd in ready:
        if fd is sock:
            data, (ip, port) = sock.recvfrom(2048)
            decrypted_data = decrypt(data, client_private_key, server_public_key)
            pkt = IP(decrypted_data)
            logger.info("From socket <==: {} --> {}".format(pkt.src, pkt.dst))
            os.write(tun, decrypted_data)

        if fd is tun:
            packet = os.read(tun, 2048)
            pkt = IP(packet)
            logger.info("From tun ==>: {} --> {}".format(pkt.src, pkt.dst))
            encrypted_data = encrypt(packet, client_private_key, server_public_key)
            sock.sendto(encrypted_data, ("10.9.0.11", 9090))
