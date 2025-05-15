#!/usr/bin/env python3

import fcntl
import struct
import os
import logging

logger = logging.getLogger(__name__)

def create_tun(TUNSETIFF, IFF_TUN, IFF_NO_PI):
    tun = os.open("/dev/net/tun", os.O_RDWR)
    ifr = struct.pack('16sH', b'tun%d', IFF_TUN | IFF_NO_PI)
    ifname_bytes = fcntl.ioctl(tun, TUNSETIFF, ifr)

    # Get the interface name
    ifname = ifname_bytes.decode('UTF-8')[:16].strip("\x00")
    logger.info("Interface Name: {}".format(ifname))
    return ifname, tun

