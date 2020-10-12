#!/bin/python3
import logging
import os
import fcntl
import struct
import hexdump
from argparse import ArgumentParser
from datetime import datetime, timedelta
from scapy.all import *
from pyopenvpn import Client, Settings


class TunClient:
    def __init__(self, args):
        self.host = args.host
        self.inited = False

    def create(self):
        TUNSETIFF = 0x400454ca
        IFF_TUN = 0x0001
        self.tfd = os.open("/dev/net/tun", os.O_RDWR)
        ifs = fcntl.ioctl(self.tfd, TUNSETIFF, struct.pack("16sH", b"t%d", IFF_TUN))
        self.tname = ifs[:16].strip(b"\x00").decode("utf8")
        print(self.tname)
        flag = fcntl.fcntl(self.tfd, fcntl.F_GETFD)
        fcntl.fcntl(self.tfd, fcntl.F_SETFD, flag | os.O_NONBLOCK)
        flag = fcntl.fcntl(self.tfd, fcntl.F_GETFD)
        if flag & os.O_NONBLOCK:
            print("xxxxxxxxx O_NONBLOCK!!")

    def config(self, ip, masklen):
        os.system("ip link set %s up" % (self.tname))
        os.system("ip link set %s mtu %i" % (self.tname, 1000))
        os.system("ip addr add %s/%i dev %s" % (ip, masklen, self.tname))

    def __call__(self, client):
        if self.inited is False:
            self.create()
            self.config(client.tunnel_ipv4, 24)
            self.inited = True

        if self.inited is True:
            incoming = client.recv_data(decode=False)
            if incoming is not None:
                hexdump(incoming)
                incoming = bytes([0, 0, 0, 0x80]) + bytes(incoming)
                os.write(self.tfd, incoming)

            data = os.read(self.tfd, 1500)
            hexdump(data)
            if data is not None:
                client.send_data(data[4:])


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO,
                        format="%(levelname)-5s:%(name)-8s: %(filename)s:%(lineno)d  %(message)s")

    parser = ArgumentParser()
    parser.add_argument('config_file', help="OpenVPN configuration file")
    parser.add_argument('host', help="Remote host to ping")
    parser.add_argument('-i', dest='interval', default=1, metavar='interval', type=int)
    parser.add_argument('-W', dest='timeout', default=5, metavar='timeout', type=int)
    parser.add_argument('-c', dest='count', default=0, metavar='count', type=int)

    args = parser.parse_args()
    c = Client(Settings.from_file(args.config_file), TunClient(args))
    c.run()

