import errno
import socket

BLOCKING_IO_ERRORS = {socket.EWOULDBLOCK, socket.EAGAIN, errno.EINPROGRESS}
SO_ORIGINAL_DST = 80
IP6T_SO_ORIGINAL_DST = 80
SYSCTL_VARS = {
    "net.ipv4.ip_forward": 1,
    "net.ipv4.conf.all.route_localnet": 1,
}

AUTO_ATTACK_DELAY = 0.1
OPCODE_DEFINITION_LIST_URL = "https://api.github.com/repos/Soreepeong/XivAlexander/contents/StaticData/OpcodeDefinition"
