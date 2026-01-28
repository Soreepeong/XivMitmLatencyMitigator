import errno
import ipaddress
import os
import socket

BLOCKING_IO_ERRORS = {socket.EWOULDBLOCK, socket.EAGAIN, errno.EINPROGRESS}
SO_ORIGINAL_DST = 80
IP6T_SO_ORIGINAL_DST = 80
SYSCTL_VARS = {
    "net.ipv4.ip_forward": 1,
    "net.ipv4.conf.all.route_localnet": 1,
    "net.ipv4.conf.all.forwarding": 1,
    "net.ipv6.conf.all.forwarding": 1,
}
NFTABLES_TABLE_NAME = f"mitm-{os.getpid():06X}"
DUMMY_NET_NAME = f"mitm-{os.getpid():06X}"

NAT64_NETWORK = ipaddress.IPv6Network("64:ff9b::/96")

AUTO_ATTACK_DELAY = 0.1
OPCODE_DEFINITION_LIST_URL = "https://api.github.com/repos/Soreepeong/XivAlexander/contents/StaticData/OpcodeDefinition"
