#!/usr/bin/env python3

import fcntl
import struct
import os
import logging

logger = logging.getLogger(__name__)

"""
TUNSETIFF appears to represent a constant value. This is an IOCTL command specifically for network devices which binds the special file /dev/net/tun to an interface, or vice versa). Defined here - https://github.com/torvalds/linux/blob/c30a13538d9f8b2a60b2f6b26abe046dea10aa12/include/uapi/linux/if_tun.h#L70

Flags used by the tunnel opening:
IFF_TUN - Whether this as a TUN device (Works with IP frames, not Ethernet frames). In client.py, this is flag is set.
IFF_NO_PI - Whether to provide packet info or not. In client.py, this is flag is set.

From: https://docs.kernel.org/networking/tuntap.html & https://www.man7.org/linux/man-pages/man2/ioctl.2.html
"""

def create_tun(TUNSETIFF, IFF_TUN, IFF_NO_PI):
    # Open the network tunnel file descriptor in read/write mode. Linux devices are represented as files in the /dev directory.
    tun = os.open("/dev/net/tun", os.O_RDWR)
    
    """
    ifr refers to a struct used to set the parameters for opening a network device with the TUNSETIFF command.
    The following line of code creates a struct from the name of the interface and the ifr_flags to be used based on the format string.

        - 16s = 16 byte string - Value is the string 'tun' converted to bytes. %d placeholder value is used when linux binds the interface, and is typically set to 0 (you can see this in the logs when the program is run - interface name: tun0).
        - H = unsigned short - This sets the flags used when opening the network tunnel (in client.py, this is set to 0x1001 or TUN device, no packet info).
    """
    ifr = struct.pack('16sH', b'tun%d', IFF_TUN | IFF_NO_PI)

    """
    This command runs a linux system call to open the network tunnel. ioctl docs show that this syscall takes 2 named params + optional args.

        ioctl(fd, op, [args]);
           fd = File Descriptor - the 'special file' representing the device to manipulate (in this case a network interface).
           op = Device-dependant Operation Code. See the summary of TUNSETIFF.
           args = technically a pointer to memory in the actual syscall, but in this case the struct with the device info set previously.
    
    ifr is of type bytes, which is immutable. Because of this, fcntl.ioctl() returns the contents of the buffer after the OS has used it. In this case, it returns the interface's name.
    """
    ifname_bytes = fcntl.ioctl(tun, TUNSETIFF, ifr)

    # Get the interface name
    ifname = ifname_bytes.decode('UTF-8')[:16].strip("\x00")
    logger.info("Interface Name: {}".format(ifname))
    return ifname, tun

