#!/usr/bin/sudo python
import argparse
import collections
import ctypes
import dataclasses
import datetime
import enum
import ipaddress
import math
import os
import random
import select
import signal
import socket
import struct
import sys
import time
import typing
import zlib

import json

import logging.handlers
import requests

ACTION_ID_AUTO_ATTACK = 0x0007
ACTION_ID_AUTO_ATTACK_MCH = 0x0008
AUTO_ATTACK_DELAY = 0.1
SO_ORIGINAL_DST = 80
OPCODE_DEFINITION_LIST_URL = "https://api.github.com/repos/Soreepeong/XivAlexander/contents/StaticData/OpcodeDefinition"

T = typing.TypeVar("T")
ArgumentTuple = collections.namedtuple("ArgumentTuple", ("region", "extra_delay", "measure_ping", "update_opcodes"))


def clamp(v: T, min_: T, max_: T) -> T:
    return max(min_, min(max_, v))


class IncompleteDataException(ValueError):
    pass


class InvalidDataException(ValueError):
    pass


class RootRequiredError(RuntimeError):
    pass


class TcpInfo(ctypes.Structure):
    """TCP_INFO struct in linux 4.2
    see /usr/include/linux/tcp.h for details"""

    __u8 = ctypes.c_uint8
    __u32 = ctypes.c_uint32
    __u64 = ctypes.c_uint64

    _fields_ = [
        ("tcpi_state", __u8),
        ("tcpi_ca_state", __u8),
        ("tcpi_retransmits", __u8),
        ("tcpi_probes", __u8),
        ("tcpi_backoff", __u8),
        ("tcpi_options", __u8),
        ("tcpi_snd_wscale", __u8, 4), ("tcpi_rcv_wscale", __u8, 4),

        ("tcpi_rto", __u32),
        ("tcpi_ato", __u32),
        ("tcpi_snd_mss", __u32),
        ("tcpi_rcv_mss", __u32),

        ("tcpi_unacked", __u32),
        ("tcpi_sacked", __u32),
        ("tcpi_lost", __u32),
        ("tcpi_retrans", __u32),
        ("tcpi_fackets", __u32),

        # Times
        ("tcpi_last_data_sent", __u32),
        ("tcpi_last_ack_sent", __u32),
        ("tcpi_last_data_recv", __u32),
        ("tcpi_last_ack_recv", __u32),
        # Metrics
        ("tcpi_pmtu", __u32),
        ("tcpi_rcv_ssthresh", __u32),
        ("tcpi_rtt", __u32),
        ("tcpi_rttvar", __u32),
        ("tcpi_snd_ssthresh", __u32),
        ("tcpi_snd_cwnd", __u32),
        ("tcpi_advmss", __u32),
        ("tcpi_reordering", __u32),

        ("tcpi_rcv_rtt", __u32),
        ("tcpi_rcv_space", __u32),

        ("tcpi_total_retrans", __u32),

        ("tcpi_pacing_rate", __u64),
        ("tcpi_max_pacing_rate", __u64),

        # RFC4898 tcpEStatsAppHCThruOctetsAcked
        ("tcpi_bytes_acked", __u64),
        # RFC4898 tcpEStatsAppHCThruOctetsReceived
        ("tcpi_bytes_received", __u64),
        # RFC4898 tcpEStatsPerfSegsOut
        ("tcpi_segs_out", __u32),
        # RFC4898 tcpEStatsPerfSegsIn
        ("tcpi_segs_in", __u32),
    ]
    del __u8, __u32, __u64

    def __repr__(self):
        keyval = ["{}={!r}".format(x[0], getattr(self, x[0]))
                  for x in self._fields_]
        fields = ", ".join(keyval)
        return "{}({})".format(self.__class__.__name__, fields)

    @classmethod
    def from_socket(cls, sock: socket.socket):
        """Takes a socket, and attempts to get TCP_INFO stats on it. Returns a
        TcpInfo struct"""
        # http://linuxgazette.net/136/pfeiffer.html
        padsize = ctypes.sizeof(TcpInfo)
        data = sock.getsockopt(socket.SOL_TCP, socket.TCP_INFO, padsize)
        # On older kernels, we get fewer bytes, pad with null to fit
        padded = data.ljust(padsize, b'\0')
        return cls.from_buffer_copy(padded)

    @classmethod
    def get_latency(cls, sock: socket.socket) -> typing.Optional[float]:
        info = cls.from_socket(sock)
        if info.tcpi_rtt:
            return info.tcpi_rtt / 1000000
        else:
            return None


class XivMessageIpcActionEffect(ctypes.LittleEndianStructure):
    _fields_ = (
        ("animation_target_actor", ctypes.c_uint32),
        ("unknown_0x004", ctypes.c_uint32),
        ("action_id", ctypes.c_uint32),
        ("global_effect_counter", ctypes.c_uint32),
        ("animation_lock_duration", ctypes.c_float),
        ("unknown_target_id", ctypes.c_uint32),
        ("source_sequence", ctypes.c_uint16),
        ("rotation", ctypes.c_uint16),
        ("action_animation_id", ctypes.c_uint16),
        ("variation", ctypes.c_uint8),
        ("effect_display_type", ctypes.c_uint8),
        ("unknonw_0x020", ctypes.c_uint8),
        ("effect_count", ctypes.c_uint8),
        ("padding_0x022", ctypes.c_uint16),
    )

    animation_target_actor: typing.Union[int, ctypes.c_uint32]
    unknown_0x004: typing.Union[int, ctypes.c_uint32]
    action_id: typing.Union[int, ctypes.c_uint32]
    global_effect_counter: typing.Union[int, ctypes.c_uint32]
    animation_lock_duration: typing.Union[float, ctypes.c_float]
    unknown_target_id: typing.Union[int, ctypes.c_uint32]
    source_sequence: typing.Union[int, ctypes.c_uint16]
    rotation: typing.Union[int, ctypes.c_uint16]
    action_animation_id: typing.Union[int, ctypes.c_uint16]
    variation: typing.Union[int, ctypes.c_uint8]
    effect_display_type: typing.Union[int, ctypes.c_uint8]
    unknown_0x020: typing.Union[int, ctypes.c_uint8]
    effect_count: typing.Union[int, ctypes.c_uint8]
    padding_0x022: typing.Union[int, ctypes.c_uint16]


class XivMessageIpcActorControlCategory(enum.IntEnum):
    CancelCast = 0x000f
    Rollback = 0x02bc


class XivMessageIpcActorControl(ctypes.LittleEndianStructure):
    _fields_ = (
        ("category_int", ctypes.c_uint16),
        ("padding_0x002", ctypes.c_uint16),
        ("param_1", ctypes.c_uint32),
        ("param_2", ctypes.c_uint32),
        ("param_3", ctypes.c_uint32),
        ("param_4", ctypes.c_uint32),
        ("padding_0x014", ctypes.c_uint32),
    )

    category_int: typing.Union[int, ctypes.c_uint16]
    padding_0x002: typing.Union[int, ctypes.c_uint16]
    param_1: typing.Union[int, ctypes.c_uint32]
    param_2: typing.Union[int, ctypes.c_uint32]
    param_3: typing.Union[int, ctypes.c_uint32]
    param_4: typing.Union[int, ctypes.c_uint32]
    padding_0x014: typing.Union[int, ctypes.c_uint32]

    @property
    def category(self):
        try:
            return XivMessageIpcActorControlCategory(self.category_int)
        except ValueError:
            return None

    @category.setter
    def category(self, value: typing.Union[int, XivMessageIpcActorControlCategory]):
        self.category_int = int(value)


class XivMessageIpcActorControlSelf(ctypes.LittleEndianStructure):
    _fields_ = (
        ("category_int", ctypes.c_uint16),
        ("padding_0x002", ctypes.c_uint16),
        ("param_1", ctypes.c_uint32),
        ("param_2", ctypes.c_uint32),
        ("param_3", ctypes.c_uint32),
        ("param_4", ctypes.c_uint32),
        ("param_5", ctypes.c_uint32),
        ("param_6", ctypes.c_uint32),
        ("padding_0x01c", ctypes.c_uint32),
    )

    category_int: typing.Union[int, ctypes.c_uint16]
    padding_0x002: typing.Union[int, ctypes.c_uint16]
    param_1: typing.Union[int, ctypes.c_uint32]
    param_2: typing.Union[int, ctypes.c_uint32]
    param_3: typing.Union[int, ctypes.c_uint32]
    param_4: typing.Union[int, ctypes.c_uint32]
    param_5: typing.Union[int, ctypes.c_uint32]
    param_6: typing.Union[int, ctypes.c_uint32]
    padding_0x01c: typing.Union[int, ctypes.c_uint32]

    @property
    def category(self):
        try:
            return XivMessageIpcActorControlCategory(self.category_int)
        except ValueError:
            return None

    @category.setter
    def category(self, value: typing.Union[int, XivMessageIpcActorControlCategory]):
        self.category_int = int(value)


class XivMessageIpcActorCast(ctypes.LittleEndianStructure):
    _fields_ = (
        ("action_id", ctypes.c_uint16),
        ("skill_type", ctypes.c_uint8),
        ("unknown_0x003", ctypes.c_uint8),
        ("action_id_2", ctypes.c_uint16),
        ("unknown_0x006", ctypes.c_uint16),
        ("cast_time", ctypes.c_float),
        ("target_id", ctypes.c_uint32),
        ("rotation", ctypes.c_float),
        ("unknown_0x014", ctypes.c_uint32),
        ("x", ctypes.c_uint16),
        ("y", ctypes.c_uint16),
        ("z", ctypes.c_uint16),
        ("unknown_0x01e", ctypes.c_uint16),
    )

    action_id: typing.Union[int, ctypes.c_uint16]
    skill_type: typing.Union[int, ctypes.c_uint8]
    unknown_0x003: typing.Union[int, ctypes.c_uint8]
    action_id_2: typing.Union[int, ctypes.c_uint16]
    unknown_0x006: typing.Union[int, ctypes.c_uint16]
    cast_time: typing.Union[float, ctypes.c_float]
    target_id: typing.Union[int, ctypes.c_uint32]
    rotation: typing.Union[float, ctypes.c_float]
    unknown_0x014: typing.Union[int, ctypes.c_uint32]
    x: typing.Union[int, ctypes.c_uint16]
    y: typing.Union[int, ctypes.c_uint16]
    z: typing.Union[int, ctypes.c_uint16]
    unknown_0x01e: typing.Union[int, ctypes.c_uint16]


class XivMessageIpcActionRequest(ctypes.LittleEndianStructure):
    _fields_ = (
        ("unknown_0x000", ctypes.c_uint8),
        ("type", ctypes.c_uint8),
        ("unknown_0x002", ctypes.c_uint16),
        ("action_id", ctypes.c_uint32),
        ("sequence", ctypes.c_uint16),
        ("unknown_0x00a", ctypes.c_uint16),
        ("unknown_0x00c", ctypes.c_uint32),
        ("unknown_0x010", ctypes.c_uint32),
        ("target_id", ctypes.c_uint32),
        ("item_source_slot", ctypes.c_uint16),
        ("item_source_container", ctypes.c_uint16),
        ("unknown_0x01c", ctypes.c_uint32),
    )

    unknown_0x000: typing.Union[int, ctypes.c_uint8]
    type: typing.Union[int, ctypes.c_uint8]
    unknown_0x002: typing.Union[int, ctypes.c_uint16]
    action_id: typing.Union[int, ctypes.c_uint32]
    sequence: typing.Union[int, ctypes.c_uint16]
    unknown_0x00a: typing.Union[int, ctypes.c_uint16]
    unknown_0x00c: typing.Union[int, ctypes.c_uint32]
    unknown_0x010: typing.Union[int, ctypes.c_uint32]
    target_id: typing.Union[int, ctypes.c_uint32]
    item_source_slot: typing.Union[int, ctypes.c_uint16]
    item_source_container: typing.Union[int, ctypes.c_uint16]
    unknown_0x01c: typing.Union[int, ctypes.c_uint32]


class XivMessageIpcCustomOriginalWaitTime(ctypes.LittleEndianStructure):
    _fields_ = (
        ("source_sequence", ctypes.c_uint16),
        ("padding_0x002", ctypes.c_uint16),
        ("original_wait_time", ctypes.c_float),
    )

    source_sequence: typing.Union[int, ctypes.c_uint16]
    padding_0x002: typing.Union[int, ctypes.c_uint16] = 0
    original_wait_time: typing.Union[float, ctypes.c_float]


class XivMessageIpcType(enum.IntEnum):
    UnknownButInterested = 0x0014
    XivMitmLatencyMitigatorCustom = 0xe852


class XivMitmLatencyMitigatorCustomSubtype(enum.IntEnum):
    OriginalWaitTime = 0x0000


class XivMessageIpcHeader(ctypes.LittleEndianStructure):
    _fields_ = (
        ("type_int", ctypes.c_uint16),
        ("subtype", ctypes.c_uint16),
        ("unknown_0x004", ctypes.c_uint16),
        ("server_id", ctypes.c_uint16),
        ("epoch", ctypes.c_uint32),
        ("unknown_0x00c", ctypes.c_uint32),
    )

    type_int: typing.Union[int, ctypes.c_uint16]
    subtype: typing.Union[int, ctypes.c_uint16]
    unknown_0x004: typing.Union[int, ctypes.c_uint16]
    server_id: typing.Union[int, ctypes.c_uint16]
    epoch: typing.Union[int, ctypes.c_uint32]
    unknown_0x00c: typing.Union[int, ctypes.c_uint32]

    @property
    def type(self):
        try:
            return XivMessageIpcType(self.type_int)
        except ValueError:
            return None

    @type.setter
    def type(self, value: typing.Union[int, XivMessageIpcType]):
        self.type_int = int(value)


class XivMessageType(enum.IntEnum):
    Ipc = 3


class XivMessageHeader(ctypes.LittleEndianStructure):
    _fields_ = (
        ("length", ctypes.c_uint32),
        ("source_actor", ctypes.c_uint32),
        ("target_actor", ctypes.c_uint32),
        ("type_int", ctypes.c_uint16),
        ("unknown_0x00e", ctypes.c_uint16),
    )

    length: typing.Union[int, ctypes.c_uint32]
    source_actor: typing.Union[int, ctypes.c_uint32]
    target_actor: typing.Union[int, ctypes.c_uint32]
    type_int: typing.Union[int, ctypes.c_uint16]
    unknown_0x00e: typing.Union[int, ctypes.c_uint16]

    @property
    def type(self):
        try:
            return XivMessageType(self.type_int)
        except ValueError:
            return None

    @type.setter
    def type(self, value: typing.Union[int, XivMessageType]):
        self.type_int = int(value)


class XivBundleHeader(ctypes.LittleEndianStructure):
    MAGIC_CONSTANT_1: typing.ClassVar[bytes] = b"\x52\x52\xa0\x41\xff\x5d\x46\xe2\x7f\x2a\x64\x4d\x7b\x99\xc4\x75"
    MAGIC_CONSTANT_2: typing.ClassVar[bytes] = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    MAX_LENGTH: typing.ClassVar[int] = 65536

    _fields_ = (
        ("magic", ctypes.c_byte * 16),
        ("timestamp", ctypes.c_uint64),
        ("length", ctypes.c_uint32),
        ("conn_type", ctypes.c_uint16),
        ("message_count", ctypes.c_uint16),
        ("encoding", ctypes.c_uint8),
        ("zlib_compressed", ctypes.c_uint8),
        ("unknown_0x022", ctypes.c_uint16),
        ("unknown_0x024", ctypes.c_uint32),
    )

    magic: typing.Union[bytearray, ctypes.c_byte * 16]
    timestamp: typing.Union[int, ctypes.c_uint64]
    length: typing.Union[int, ctypes.c_uint32]
    conn_type: typing.Union[int, ctypes.c_uint16]
    message_count: typing.Union[int, ctypes.c_uint16]
    encoding: typing.Union[int, ctypes.c_uint8]
    zlib_compressed: typing.Union[int, ctypes.c_uint8]
    unknown_0x022: typing.Union[int, ctypes.c_uint16]
    unknown_0x024: typing.Union[int, ctypes.c_uint32]

    @classmethod
    def find(cls, data: typing.Union[bytearray, memoryview]):
        offset = 0
        while offset < len(data):
            available_bytes = len(data) - offset
            if available_bytes >= len(cls.MAGIC_CONSTANT_1):
                mc1 = data.find(cls.MAGIC_CONSTANT_1, offset)
                mc2 = data.find(cls.MAGIC_CONSTANT_2, offset)
            else:
                mc1 = data.find(cls.MAGIC_CONSTANT_1[:available_bytes], offset)
                mc2 = data.find(cls.MAGIC_CONSTANT_2[:available_bytes], offset)
            if mc1 == -1:
                i = mc2
            elif mc2 == -1:
                i = mc1
            else:
                i = min(mc1, mc2)
            if i == -1:  # no hope
                yield data[offset:]
                offset = len(data)
                break
            if i != offset:
                yield data[offset:i]
                offset = i

            if len(data) < offset + ctypes.sizeof(cls):
                break

            try:
                bundle_header = XivBundleHeader.from_buffer(data, offset)
                if len(data) < offset + bundle_header.length:
                    break

                bundle_data = data[offset + ctypes.sizeof(bundle_header):offset + bundle_header.length]
                offset += bundle_header.length
                if bundle_header.zlib_compressed:
                    bundle_data = bytearray(zlib.decompress(bundle_data))

                bundle_offset = 0
                messages = list()
                for i in range(bundle_header.message_count):
                    try:
                        message_header = XivMessageHeader.from_buffer(bundle_data, bundle_offset)
                        message_data = bundle_data[bundle_offset:][ctypes.sizeof(message_header):message_header.length]
                        messages.append((message_header, message_data))
                    except IncompleteDataException:
                        raise InvalidDataException
                    bundle_offset += message_header.length
                    if bundle_offset > len(bundle_data):
                        raise InvalidDataException
                yield bundle_header, messages
            except IncompleteDataException:
                break
            except InvalidDataException:
                yield data[offset:offset + 1]
                offset += 1
        return offset


@dataclasses.dataclass
class OpcodeDefinition:
    Name: str
    C2S_ActionRequest: int
    C2S_ActionRequestGroundTargeted: int
    S2C_ActionEffect01: int
    S2C_ActionEffect08: int
    S2C_ActionEffect16: int
    S2C_ActionEffect24: int
    S2C_ActionEffect32: int
    S2C_ActorCast: int
    S2C_ActorControl: int
    S2C_ActorControlSelf: int
    Server_IpRange: typing.List[typing.Union[ipaddress.IPv4Network,
                                             typing.Tuple[ipaddress.IPv4Address, ipaddress.IPv4Address]]]
    Server_PortRange: typing.List[typing.Tuple[int, int]]

    @classmethod
    def from_dict(cls, data: dict):
        kwargs = {}
        for field in dataclasses.fields(cls):
            field: dataclasses.Field
            if field.type is int:
                kwargs[field.name] = int(data[field.name], 0)
            elif field.name == "Server_IpRange":
                iplist = []
                for partstr in data[field.name].split(","):
                    part = [x.strip() for x in partstr.split("-")]
                    try:
                        if len(part) == 1:
                            iplist.append(ipaddress.IPv4Network(part[0]))
                        elif len(part) == 2:
                            iplist.append(tuple(sorted(ipaddress.IPv4Address(x) for x in part)))
                        else:
                            raise ValueError
                    except ValueError:
                        print("Skipping invalid IP address definition", partstr)
                kwargs[field.name] = iplist
            elif field.name == "Server_PortRange":
                portlist = []
                for partstr in data[field.name].split(","):
                    part = [x.strip() for x in partstr.split("-")]
                    try:
                        if len(part) == 1:
                            portlist.append((int(part[0], 0), int(part[0], 0)))
                        elif len(part) == 2:
                            portlist.append((int(part[0], 0), int(part[1], 0)))
                        else:
                            raise ValueError
                    except ValueError:
                        print("Skipping invalid port definition", partstr)
                kwargs[field.name] = portlist
            else:
                kwargs[field.name] = None if data[field.name] is None else field.type(data[field.name])
        return OpcodeDefinition(**kwargs)

    def is_request(self, opcode: int):
        return (opcode == self.C2S_ActionRequest
                or opcode == self.C2S_ActionRequestGroundTargeted)

    def is_action_effect(self, opcode: int):
        return (opcode == self.S2C_ActionEffect01
                or opcode == self.S2C_ActionEffect08
                or opcode == self.S2C_ActionEffect16
                or opcode == self.S2C_ActionEffect24
                or opcode == self.S2C_ActionEffect32)


@dataclasses.dataclass
class SocketSet:
    source: socket.socket
    target: socket.socket
    log_prefix: str
    process_function: callable
    incoming: typing.Optional[bytearray] = dataclasses.field(default_factory=bytearray)
    outgoing: typing.Optional[bytearray] = dataclasses.field(default_factory=bytearray)


@dataclasses.dataclass
class PendingAction:
    action_id: int
    sequence: int
    request_timestamp: float = dataclasses.field(default_factory=time.time)
    response_timestamp: float = 0
    original_wait_time: float = 0
    is_cast: bool = False


class NumericStatisticsTracker:
    def __init__(self, count: int, max_age: typing.Optional[float] = None):
        self._count = count
        self._max_age = max_age
        self._values = collections.deque()
        self._expiry = collections.deque()

    def add(self, v: float):
        self._values.append(v)
        if self._max_age is not None:
            self._expiry.append(time.time() + self._max_age)
        while len(self._values) > self._count:
            self._values.popleft()
            if self._max_age is not None:
                self._expiry.popleft()

    def min(self) -> typing.Optional[float]:
        return min(self._values) if self._values else None

    def max(self) -> typing.Optional[float]:
        return max(self._values) if self._values else None

    def mean(self) -> typing.Optional[float]:
        return sum(self._values) / len(self._values) if self._values else None

    def median(self) -> typing.Optional[float]:
        if not self._values:
            return None
        s = list(sorted(self._values))
        if len(s) % 2 == 0:
            return (s[len(s) // 2] + s[len(s) // 2 - 1]) / 2
        else:
            return s[len(s) // 2]

    def deviation(self) -> typing.Optional[float]:
        if not self._values:
            return None
        mean = self.mean()
        return math.sqrt(sum(pow(x - mean, 2) for x in self._values) / len(self._values))

    def __bool__(self):
        return not not self._values


class Connection:
    pending_actions: typing.Deque[PendingAction] = collections.deque()
    opcodes: typing.Optional[OpcodeDefinition]

    def __init__(self, sock: socket.socket, source: typing.Tuple[str, int],
                 definitions: typing.List[OpcodeDefinition], args: ArgumentTuple):
        self.args = args

        log_path = f"/tmp/xmlm.{datetime.datetime.now():%Y%m%d%H%M%S}.{os.getpid()}.log"
        logging.basicConfig(level=logging.INFO, force=True,
                            format="%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s",
                            handlers=[
                                logging.FileHandler(log_path, "w"),
                                logging.StreamHandler(sys.stderr),
                            ])
        logging.info(f"Log will be saved to {log_path}")

        self.source = source
        self.downstream = sock
        self.downstream.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
        self.downstream.setsockopt(socket.SOL_TCP, socket.TCP_QUICKACK, 1)
        self.downstream.setblocking(False)

        self.screen_prefix = f"[{os.getpid():>6}]"
        srv_port, srv_ip = struct.unpack("!2xH4s8x", self.downstream.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16))
        self.destination = (socket.inet_ntoa(srv_ip), srv_port)
        self.upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.upstream.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
        self.upstream.setsockopt(socket.SOL_TCP, socket.TCP_QUICKACK, 1)
        self.upstream.setblocking(False)

        self.last_animation_lock_ends_at = 0
        self.last_successful_request = PendingAction(0, 0)

        self.latency_application = NumericStatisticsTracker(10)
        self.latency_upstream = NumericStatisticsTracker(10)
        self.latency_downstream = NumericStatisticsTracker(10)
        self.latency_exaggeration = NumericStatisticsTracker(10, 30.)

        dest_ip = ipaddress.IPv4Address(self.destination[0])
        for definition in definitions:
            for iprange in definition.Server_IpRange:
                if isinstance(iprange, ipaddress.IPv4Network):
                    if dest_ip in iprange:
                        break
                else:
                    if iprange[0] <= dest_ip <= iprange[1]:
                        break
            else:
                continue

            for port1, port2 in definition.Server_PortRange:
                if port1 <= self.destination[1] <= port2:
                    break
            else:
                continue

            dn = definition.Name
            self.opcodes = definition
            break
        else:
            self.opcodes = None
            dn = "-"
        logging.info(f"New[{dn}] {self.downstream.getsockname()} {self.downstream.getpeername()} {self.destination}")

    def to_upstream(self, bundle_header: XivBundleHeader,
                    messages: typing.List[typing.Tuple[XivMessageHeader, bytearray]]):
        for message_header, message_data in messages:
            if message_header.type != XivMessageType.Ipc:
                continue
            try:
                ipc = XivMessageIpcHeader.from_buffer(message_data)
                ipc_data = message_data[ctypes.sizeof(ipc):]
                if ipc.type != XivMessageIpcType.UnknownButInterested:
                    continue
                if self.opcodes.is_request(ipc.subtype):
                    request = XivMessageIpcActionRequest.from_buffer(ipc_data)
                    self.pending_actions.append(PendingAction(request.action_id, request.sequence))

                    # If somehow latest action request has been made before last animation lock end time, keep it.
                    # Otherwise...
                    if self.pending_actions[-1].request_timestamp > self.last_animation_lock_ends_at:

                        # If there was no action queued to begin with before the current one,
                        # update the base lock time to now.
                        if len(self.pending_actions) == 1:
                            self.last_animation_lock_ends_at = self.pending_actions[-1].request_timestamp

                    logging.info(f"C2S_ActionRequest: actionId={request.action_id:04x} sequence={request.sequence:04x}")
            except (InvalidDataException, IncompleteDataException):
                continue
        return bundle_header, messages

    def to_downstream(self, bundle_header: XivBundleHeader,
                      messages: typing.List[typing.Tuple[XivMessageHeader, bytearray]]):
        message_insertions: typing.List[typing.Tuple[int, XivMessageHeader, bytearray]] = []
        wait_time_dict: typing.Dict[int, float] = {}
        for i, (message_header, message_data) in enumerate(messages):
            if not message_header.type == XivMessageType.Ipc:
                continue
            if message_header.source_actor != message_header.target_actor:
                continue
            try:
                ipc = XivMessageIpcHeader.from_buffer(message_data)
                ipc_data = message_data[ctypes.sizeof(ipc):]
                if (ipc.type == XivMessageIpcType.XivMitmLatencyMitigatorCustom
                        and ipc.subtype == XivMitmLatencyMitigatorCustomSubtype.OriginalWaitTime):
                    data = XivMessageIpcCustomOriginalWaitTime.from_buffer(ipc_data)
                    wait_time_dict[data.source_sequence] = data.original_wait_time
                if ipc.type != XivMessageIpcType.UnknownButInterested:
                    continue
                if self.opcodes.is_action_effect(ipc.subtype):
                    effect = XivMessageIpcActionEffect.from_buffer(ipc_data)
                    original_wait_time = wait_time_dict.get(effect.source_sequence, effect.animation_lock_duration)
                    wait_time = original_wait_time
                    now = time.time()
                    extra_message = ""

                    if effect.source_sequence == 0:
                        # Process actions originating from server.
                        if (not self.last_successful_request.is_cast
                                and self.last_successful_request.sequence
                                and self.last_animation_lock_ends_at > now):
                            self.last_successful_request.action_id = effect.action_id
                            self.last_successful_request.sequence = 0
                            self.last_animation_lock_ends_at += (
                                    (original_wait_time + now)
                                    - (self.last_successful_request.original_wait_time
                                       + self.last_successful_request.response_timestamp)
                            )
                            self.last_animation_lock_ends_at = max(self.last_animation_lock_ends_at,
                                                                   now + AUTO_ATTACK_DELAY)
                            wait_time = self.last_animation_lock_ends_at - now

                        extra_message += " serverOriginated"

                    else:
                        while self.pending_actions and self.pending_actions[0].sequence != effect.source_sequence:
                            item = self.pending_actions.popleft()
                            logging.info(f"\t┎ ActionRequest ignored for processing: actionId={item.action_id:04x} "
                                         f"sequence={item.sequence:04x}")

                        if self.pending_actions:
                            self.last_successful_request = self.pending_actions.popleft()
                            self.last_successful_request.response_timestamp = now
                            self.last_successful_request.original_wait_time = original_wait_time
                            # 100ms animation lock after cast ends stays.
                            # Modify animation lock duration for instant actions only.
                            # Since no other action is in progress right before the cast ends,
                            # we can safely replace the animation lock with the latest after-cast lock.
                            if not self.last_successful_request.is_cast:
                                rtt = (self.last_successful_request.response_timestamp
                                       - self.last_successful_request.request_timestamp)
                                self.latency_application.add(rtt)
                                extra_message += f" rtt={rtt * 1000:.0f}ms"
                                delay, message_append = self.resolve_adjusted_extra_delay(rtt)
                                extra_message += message_append
                                self.last_animation_lock_ends_at += original_wait_time + delay
                                wait_time = self.last_animation_lock_ends_at - now

                    if math.isclose(wait_time, original_wait_time):
                        logging.info(f"S2C_ActionEffect: actionId={effect.action_id:04x} "
                                     f"sourceSequence={effect.source_sequence:04x} "
                                     f"wait={int(original_wait_time * 1000)}ms{extra_message}")
                    else:
                        logging.info(f"S2C_ActionEffect: actionId={effect.action_id:04x} "
                                     f"sourceSequence={effect.source_sequence:04x} "
                                     f"wait={int(original_wait_time * 1000)}ms->{int(wait_time * 1000)}ms"
                                     f"{extra_message}")
                        effect.animation_lock_duration = max(0., wait_time)

                        custom_message_data = bytearray(ctypes.sizeof(XivMessageIpcCustomOriginalWaitTime)
                                                        + ctypes.sizeof(XivMessageIpcHeader))

                        custom_ipc = XivMessageIpcHeader.from_buffer(custom_message_data)
                        custom_ipc.type = XivMessageIpcType.XivMitmLatencyMitigatorCustom
                        custom_ipc.subtype = XivMitmLatencyMitigatorCustomSubtype.OriginalWaitTime
                        custom_ipc.server_id = ipc.server_id
                        custom_ipc.epoch = ipc.epoch

                        custom_ipc_original_wait_time = XivMessageIpcCustomOriginalWaitTime.from_buffer(
                            custom_message_data, ctypes.sizeof(custom_ipc))
                        custom_ipc_original_wait_time.source_sequence = effect.source_sequence

                        custom_message = XivMessageHeader()
                        custom_message.source_actor = message_header.source_actor
                        custom_message.target_actor = message_header.target_actor
                        custom_message.type = XivMessageType.Ipc
                        custom_message.length = sum(ctypes.sizeof(x) for x in (custom_ipc_original_wait_time,
                                                                               custom_ipc, custom_message))

                        message_insertions.append((i, custom_message, custom_message_data))

                elif ipc.subtype == self.opcodes.S2C_ActorControlSelf:
                    control = XivMessageIpcActorControlSelf.from_buffer(ipc_data)
                    if control.category == XivMessageIpcActorControlCategory.Rollback:
                        action_id = control.param_3
                        source_sequence = control.param_6
                        while (self.pending_actions
                               and (
                                       (source_sequence and self.pending_actions[0].sequence != source_sequence)
                                       or (not source_sequence and self.pending_actions[0].action_id != action_id)
                               )):
                            item = self.pending_actions.popleft()
                            logging.info(f"\t┎ ActionRequest ignored for processing: actionId={item.action_id:04x} "
                                         f"sequence={item.sequence:04x}")

                        if self.pending_actions:
                            self.pending_actions.popleft()

                        logging.info(f"S2C_ActorControlSelf/ActionRejected: "
                                     f"actionId={action_id:04x} "
                                     f"sourceSequence={source_sequence:08x}")

                elif ipc.subtype == self.opcodes.S2C_ActorControl:
                    control = XivMessageIpcActorControl.from_buffer(ipc_data)
                    if control.category == XivMessageIpcActorControlCategory.CancelCast:
                        action_id = control.param_3
                        while self.pending_actions and self.pending_actions[0].action_id != action_id:
                            item = self.pending_actions.popleft()
                            logging.info(f"\t┎ ActionRequest ignored for processing: actionId={item.action_id:04x} "
                                         f"sequence={item.sequence:04x}")

                        if self.pending_actions:
                            self.pending_actions.popleft()

                        logging.info(f"S2C_ActorControl/CancelCast: actionId={action_id:04x}")

                elif ipc.subtype == self.opcodes.S2C_ActorCast:
                    cast = XivMessageIpcActorCast.from_buffer(ipc_data)

                    # Mark that the last request was a cast.
                    # If it indeed is a cast, the game UI will block the user from generating additional requests,
                    # so first item is guaranteed to be the cast action.
                    if self.pending_actions:
                        self.pending_actions[0].is_cast = True

                    logging.info(f"S2C_ActorCast: actionId={cast.action_id:04x} type={cast.skill_type:04x} "
                                 f"action_id_2={cast.action_id_2:04x} time={cast.cast_time:.3f} "
                                 f"target_id={cast.target_id:08x}")

            except (InvalidDataException, IncompleteDataException):
                continue
        for i, message_header, message_data in reversed(message_insertions):
            messages.insert(i, (message_header, message_data))
        return bundle_header, messages

    def run(self):
        bundle_header: XivBundleHeader
        messages: typing.List[typing.Tuple[XivMessageHeader, bytearray]]

        self.upstream.settimeout(3)
        with self.downstream, self.upstream:
            try:
                self.upstream.connect((str(self.destination[0]), self.destination[1]))
                self.upstream.settimeout(None)

                check_targets = {
                    self.downstream: SocketSet(self.downstream, self.upstream, "D->U", self.to_upstream),
                    self.upstream: SocketSet(self.upstream, self.downstream, "U->D", self.to_downstream),
                }
                while True:
                    rlist = [
                        k for k, v in check_targets.items() if v.incoming is not None
                    ]
                    wlist = [
                        k for k, v in check_targets.items() if v.outgoing
                    ]
                    if not rlist and not wlist:
                        break

                    rlist, wlist, _ = select.select(rlist, wlist, [], 60)
                    if not rlist and not wlist:  # timeout or empty
                        break

                    for target in check_targets.values():
                        if target.source in rlist:
                            try:
                                data = target.source.recv(65536)
                                if not data:
                                    raise EOFError
                            except (OSError, EOFError):
                                logging.info(f"{target.log_prefix} Read finish")
                                target.incoming = None
                                continue

                            if self.opcodes is None:
                                target.outgoing.extend(data)
                            else:
                                target.incoming.extend(data)
                                it = XivBundleHeader.find(bytearray(target.incoming))
                                while True:
                                    try:
                                        bundle = next(it)
                                    except StopIteration as e:
                                        del target.incoming[0:e.value]
                                        break

                                    if isinstance(bundle, (bytes, bytearray)):
                                        logging.info(f"{target.log_prefix} discarded " +
                                                     " ".join(f"{x:02x}" for x in bundle))
                                        target.outgoing.extend(bundle)
                                    else:
                                        bundle_header, messages = bundle
                                        bundle_header, messages = target.process_function(bundle_header, messages)

                                        message_bytes = bytearray()
                                        for message_header, message_data in messages:
                                            # noinspection PyTypeChecker
                                            message_bytes.extend(bytes(message_header))
                                            message_bytes.extend(message_data)
                                        if bundle_header.zlib_compressed:
                                            message_bytes = zlib.compress(message_bytes)

                                        bundle_header.message_count = len(messages)
                                        bundle_header.length = ctypes.sizeof(bundle_header) + len(message_bytes)

                                        # noinspection PyTypeChecker
                                        target.outgoing.extend(bytes(bundle_header))
                                        target.outgoing.extend(message_bytes)

                    for target in check_targets.values():
                        if target.outgoing is None:
                            continue
                        if target.outgoing:
                            try:
                                target.target.send(target.outgoing)
                            except socket.error as e:
                                if e.errno not in (socket.EWOULDBLOCK, socket.EAGAIN):
                                    raise
                                continue
                            target.outgoing.clear()
                        if target.incoming is None:
                            target.outgoing = None
                            logging.info(f"{target.log_prefix} Source read and target write shutdown")
                            try:
                                target.source.shutdown(socket.SHUT_RD)
                            except OSError:
                                pass
                            try:
                                target.target.shutdown(socket.SHUT_WR)
                            except OSError:
                                pass
                logging.info("Closed")
            except Exception as e:
                logging.info(f"Closed, exception occurred: {type(e)} {e}", exc_info=True)
                return -1
            except KeyboardInterrupt:
                # do no cleanup
                # noinspection PyProtectedMember,PyUnresolvedReferences
                os._exit(0)
            return 0

    def resolve_adjusted_extra_delay(self, rtt: float) -> typing.Tuple[float, str]:
        if not self.args.measure_ping:
            return self.args.extra_delay, ""

        extra_message = ""
        latency_downstream = TcpInfo.get_latency(self.downstream)
        latency_upstream = TcpInfo.get_latency(self.upstream)
        if latency_downstream is not None:
            self.latency_downstream.add(latency_downstream)
            extra_message += f" downstream={int(latency_downstream * 1000)}ms"
        if latency_upstream is not None:
            self.latency_upstream.add(latency_upstream)
            extra_message += f" upstream={int(latency_upstream * 1000)}ms"
        if latency_downstream is None or latency_upstream is None:
            return self.args.extra_delay, extra_message

        latency = latency_downstream + latency_upstream
        if latency > rtt:
            self.latency_exaggeration.add(latency - rtt)

        if self.latency_exaggeration:
            exaggeration = self.latency_exaggeration.median()
            extra_message += f" latency={latency * 1000:.0f}ms->{1000 * (latency - exaggeration):.0f}ms"
            latency -= exaggeration
        else:
            extra_message += f" latency={latency * 1000:.0f}ms"

        if rtt > 100 and latency < 5:
            extra_message += " unreliableLatency"
            return self.args.extra_delay, extra_message

        rtt_min = self.latency_application.min()
        rtt_mean = self.latency_application.mean()
        rtt_deviation = self.latency_application.deviation()
        latency_mean = self.latency_upstream.mean() + self.latency_downstream.mean()
        latency_deviation = self.latency_upstream.deviation() + self.latency_downstream.deviation()

        # Correct latency and server response time values in case of outliers.
        latency = clamp(latency, latency_mean - latency_deviation, latency_mean + latency_deviation)
        rtt = clamp(rtt, rtt_mean - rtt_deviation, rtt_mean + rtt_deviation)

        # Estimate latency based on server response time statistics.
        latency_estimate = (rtt + rtt_min + rtt_mean) / 3 - rtt_deviation
        extra_message += f" latencyEstimate={latency_estimate * 1000:.0f}ms"

        # Correct latency value based on estimate if server response time is stable.
        latency = max(latency_estimate, latency)

        # This delay is based on server's processing time.
        # If the server is busy, everyone should feel the same effect.
        # * Only the player's ping is taken out of the equation. (- latencyAdjusted)
        # * Prevent accidentally too high ExtraDelay. (Clamp above 1ms)
        delay = clamp(rtt - latency, 0.001, self.args.extra_delay * 2)
        extra_message += f" delayAdjusted={delay * 1000:.0f}ms"
        return delay, extra_message


def load_definitions(update_opcodes: bool):
    try:
        if update_opcodes:
            raise RuntimeError("Force update requested")
        if os.path.getmtime("definitions.json") + 60 * 60 < time.time():
            raise RuntimeError("Definitions file older than an hour")
        with open("definitions.json", "r") as fp:
            definitions = [OpcodeDefinition.from_dict(x) for x in json.load(fp)]
    except RuntimeError as e:
        logging.info(f"Failed to read previous opcode definition files: {e}")
        definitions_raw = []

        logging.info("Downloading opcode definition files...")
        try:
            rq = requests.get(OPCODE_DEFINITION_LIST_URL)
            rq.raise_for_status()
            filelist = json.loads(rq.content)

            for f in filelist:
                rq = requests.get(f["download_url"])
                rq.raise_for_status()
                data = json.loads(rq.content)
                data["Name"] = f["name"]
                definitions_raw.append(data)
        except (requests.HTTPError, ConnectionError, json.JSONDecodeError):
            logging.exception(f"Failed to load opcode definition")
            return -1
        with open("definitions.json", "w") as fp:
            json.dump(definitions_raw, fp)
        definitions = [OpcodeDefinition.from_dict(x) for x in definitions_raw]
    return definitions


def load_rules(port: int, definitions: typing.List[OpcodeDefinition]) -> typing.Set[str]:
    rules = set()
    for definition in definitions:
        for iprange in definition.Server_IpRange:
            rule = [
                "-p tcp",
                "-m multiport",
                "--dports", ",".join(str(port1) if port1 == port2 else f"{port1}:{port2}"
                                     for port1, port2 in definition.Server_PortRange)
            ]
            if isinstance(iprange, ipaddress.IPv4Network):
                rule += ["-d", str(iprange)]
            else:
                rule += ["-m", "iprange", "--dst-range", f"{iprange[0]}-{iprange[1]}"]
            rule.append(f"-j REDIRECT --to {port}")
            rules.add(" ".join(rule))
    return rules


def __main__() -> int:
    parser = argparse.ArgumentParser("XivMitmLatencyMitigator")
    parser.add_argument("-r", "--region", action="append", dest="region", default=[])
    parser.add_argument("-e", "--extra-delay", action="store", dest="extra_delay", default=0.075, type=float)
    parser.add_argument("-m", "--measure-ping", action="store_true", dest="measure_ping", default=False)
    parser.add_argument("-u", "--update-opcodes", action="store_true", dest="update_opcodes", default=False)
    args: typing.Union[ArgumentTuple, argparse.Namespace] = parser.parse_args()

    logging.basicConfig(level=logging.INFO, force=True,
                        format="%(asctime)s\t%(process)d(main)\t%(levelname)s\t%(message)s",
                        handlers=[
                            logging.StreamHandler(sys.stderr),
                        ])

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
    listener.setsockopt(socket.SOL_TCP, socket.TCP_QUICKACK, 1)
    while True:
        port = random.randint(10000, 65535)
        try:
            listener.bind(("0.0.0.0", port))
        except OSError:
            continue
        break

    definitions = load_definitions(args.update_opcodes)
    if args.region:
        definitions = [x for x in definitions if any(r.lower() in x.Name.lower() for r in args.region)]

    applied_rules = []
    err = False
    is_child = False
    cleanup_filename = os.path.basename(__file__) + ".cleanup.sh"
    if os.path.exists(cleanup_filename):
        os.system(cleanup_filename)
    try:
        with open(cleanup_filename, "w") as fp:
            fp.write("#!/bin/bash\n")
            for rule in load_rules(port, definitions):
                iptables_cmd = f"iptables -t nat -I PREROUTING {rule}"
                logging.info(f"Running: {iptables_cmd}")
                if os.system(iptables_cmd):
                    raise RootRequiredError
                applied_rules.append(rule)
                fp.write(f"iptables -t nat -D PREROUTING {rule}\n")
        os.chmod(cleanup_filename, 0o777)

        os.system("sysctl -w net.ipv4.ip_forward=1")

        listener.listen(8)
        logging.info(f"Listening on {listener.getsockname()}...")
        logging.info("Press Ctrl+C to quit.")

        child_pids = set()

        def on_child_exit(signum, frame):
            if child_pids:
                pid, status = os.waitpid(-1, os.WNOHANG)
                if pid:
                    logging.info(f"[{pid:<6}] has exit with status code {status}.")
                    child_pids.discard(pid)

        signal.signal(signal.SIGCHLD, on_child_exit)

        while True:
            for child_pid in child_pids:
                try:
                    os.kill(child_pid, 0)
                except OSError:
                    child_pids.remove(child_pid)
            try:
                sock, source = listener.accept()
            except KeyboardInterrupt:
                break

            child_pid = os.fork()
            if child_pid == 0:
                is_child = True
                child_pids.clear()
                listener.close()
                return Connection(sock, source, definitions, args).run()
            sock.close()
            child_pids.add(child_pid)

        for child_pid in child_pids:
            try:
                os.kill(child_pid, signal.SIGINT)
            except OSError:
                pass

    except RootRequiredError:
        logging.error("This program requires root permissions.\n")
        err = True

    finally:
        if not is_child:
            logging.info("Cleaning up...")
            for rule in applied_rules:
                iptables_cmd = f"iptables -t nat -D PREROUTING {rule}"
                logging.info(f"Running: {iptables_cmd}")
                exit_code = os.system(iptables_cmd)
                if exit_code:
                    logging.warning(f"\t=> Failed with exit code {exit_code}")
                    err = True
            os.remove(cleanup_filename)
            if err:
                logging.error("One or more error have occurred during cleanup.")
                return -1
            else:
                logging.info("Cleanup complete.")
                return 0


if __name__ == "__main__":
    exit(__main__())
