#!/usr/bin/sudo python

import collections
import ctypes
import dataclasses
import datetime
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

import requests

ACTION_ID_AUTO_ATTACK = 0x0007
ACTION_ID_AUTO_ATTACK_MCH = 0x0008
AUTO_ATTACK_DELAY = 0.1
SO_ORIGINAL_DST = 80
OPCODE_DEFINITION_LIST_URL = "https://api.github.com/repos/Soreepeong/XivAlexander/contents/StaticData/OpcodeDefinition"

# Server responses have been usually taking between 50ms and 100ms on below-1ms
# latency to server, so 75ms is a good average.
# The server will do sanity check on the frequency of action use requests,
# and it's very easy to identify whether you're trying to go below allowed minimum value.
# This addon is already in gray area. Do NOT decrease this value. You've been warned.
# Feel free to increase and see how does it feel like to play on high latency instead, though.
EXTRA_DELAY = 0.075

# Based on assumption that all game servers of a datacenter should exist in /24 subnet
INTL_DATACENTER_IP_NETWORK = [socket.gethostbyname(f"neolobby{i:>02}.ffxiv.com") for i in range(1, 9)]
INTL_DATACENTER_IP_NETWORK = set(ipaddress.ip_network(".".join(x.split(".")[0:3]) + ".0/24")
                                 for x in INTL_DATACENTER_IP_NETWORK)

KR_DATACENTER_IP_NETWORK = [socket.gethostbyname("lobbyf-live.ff14.co.kr")]
KR_DATACENTER_IP_NETWORK = set(ipaddress.ip_network(".".join(x.split(".")[0:3]) + ".0/24")
                               for x in KR_DATACENTER_IP_NETWORK)


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
    S2C_AddStatusEffect: int
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


definitions: typing.List[OpcodeDefinition] = []


@dataclasses.dataclass
class SocketSet:
    source: socket.socket
    target: socket.socket
    log_prefix: str
    process_function: callable
    incoming: typing.Optional[bytearray] = dataclasses.field(default_factory=bytearray)
    outgoing: typing.Optional[bytearray] = dataclasses.field(default_factory=bytearray)


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
    def from_socket(cls, sock):
        """Takes a socket, and attempts to get TCP_INFO stats on it. Returns a
        TcpInfo struct"""
        # http://linuxgazette.net/136/pfeiffer.html
        padsize = ctypes.sizeof(TcpInfo)
        data = sock.getsockopt(socket.SOL_TCP, socket.TCP_INFO, padsize)
        # On older kernels, we get fewer bytes, pad with null to fit
        padded = data.ljust(padsize, b'\0')
        return cls.from_buffer_copy(padded)


class IncompleteDataException(ValueError):
    pass


class InvalidDataException(ValueError):
    pass


class StructBase:
    DEFINITION: typing.ClassVar[struct.Struct]
    ALL_TYPES: typing.ClassVar[typing.List[str]]
    _types: typing.List[str]

    def __init_subclass__(cls, definition: str = "", **kwargs):
        cls.DEFINITION = struct.Struct(definition)
        cls.ALL_TYPES = list(x for x in typing.get_type_hints(cls).keys() if x[0] != "_" and x.islower())

    def __init__(self, data: bytes, offset: int):
        if len(data) - offset < self.__class__.DEFINITION.size:
            raise IncompleteDataException
        unpacked = self.__class__.DEFINITION.unpack(data[offset:offset + self.__class__.DEFINITION.size])
        self._types = []
        for key, value in zip(self.__class__.ALL_TYPES, unpacked):
            setattr(self, key, value)
            self._types.append(key)

    def __str__(self):
        return f"{self.__class__.__name__}({', '.join(f'{x}={getattr(self, x)}' for x in self.__class__.ALL_TYPES)})"

    def __repr__(self):
        return self.__str__()

    def __bytes__(self):
        return self.__class__.DEFINITION.pack(*[getattr(self, x) for x in self._types])


class XivMessageIpcActionEffect(StructBase, definition="<I4sIIfIHHHBB1sB2s"):
    animation_target_actor: int  # I: uint32
    unknown_1: bytes  # 4s: char x 4
    action_id: int  # I: uint32
    global_effect_counter: int  # I: uint32
    animation_lock_duration: float  # f: float
    unknown_target_id: int  # I: uint32
    source_sequence: int  # H: uint16
    rotation: int  # H: uint16
    action_animation_id: int  # H: uint16
    variation: int  # B: uint8
    effect_display_type: int  # B: uint8
    unknown_2: bytes  # 1s: char
    effect_count: int  # B: uint8
    unknown_3: bytes  # 2s: char x 2


class XivMessageIpcActorControl(StructBase, definition="<H2sIIII4s"):
    CATEGORY_CANCEL_CAST: typing.ClassVar = 0x000f

    category: int  # H: uint16
    unknown_1: bytes  # 2s: char x 2
    param_1: int  # I: uint32
    param_2: int  # I: uint32
    param_3: int  # I: uint32
    param_4: int  # I: uint32
    unknown_2: bytes  # 4s: char x 4


class XivMessageIpcActorControlSelf(StructBase, definition="<H2sIIIIII4s"):
    CATEGORY_ROLLBACK: typing.ClassVar = 0x02bc

    category: int  # H: uint16
    unknown_1: bytes  # 2s: char x 2
    param_1: int  # I: uint32
    param_2: int  # I: uint32
    param_3: int  # I: uint32
    param_4: int  # I: uint32
    param_5: int  # I: uint32
    param_6: int  # I: uint32
    unknown_2: bytes  # 4s: char x 4


class XivMessageIpcActorCast(StructBase, definition="<HB1sH2sfIf4sHHH2s"):
    action_id: int  # H: uint16
    skill_type: int  # B: uint8
    unknown_1: bytes  # 1s: char x 1
    action_id_2: int  # H: uint16
    unknown_2: bytes  # 2s: char x 2
    cast_time: float  # f: float
    target_id: int  # I: uint32
    rotation: float  # f: float
    unknown_3: bytes  # 4s: char x 4
    x: int  # H: uint16
    y: int  # H: uint16
    z: int  # H: uint16
    unknown_4: bytes  # 2s: char x 2


class XivMessageIpcActionRequest(StructBase, definition="<1sB2sIH6sQHH4s"):
    pad_0000: bytes  # 1s: char x 1
    type: int  # B: uint8
    pad_0002: bytes  # 2s: char x 2
    action_id: int  # I: uint32
    sequence: int  # H: uint16
    pad_000c: bytes  # 6s: char x 6
    target_id: int  # Q: uint64
    item_source_slot: int  # H: uint16
    item_source_container: int  # H: uint16
    unknown: bytes  # 4s: char x 4


class XivMessageIpcCustomOriginalWaitTime(StructBase, definition="<H2sf"):
    source_sequence: int  # H: uint16
    padding1: bytes  # 2s: char x 2
    original_wait_time: float  # f: float

    @classmethod
    def make(cls, source_sequence: int, original_wait_time: float):
        return XivMessageIpcCustomOriginalWaitTime(cls.DEFINITION.pack(source_sequence, b"\x00\x00",
                                                                       original_wait_time), 0)


class XivMessageIpc(StructBase, definition="<HH2sHI4s"):
    TYPE_INTERESTED: typing.ClassVar = 0x14  # not interested in anything else at the moment, hence the meaningless name
    TYPE_CUSTOM: typing.ClassVar = 0xE852

    SUBTYPE_CUSTOM_ORIGINAL_WAIT_TIME = 0x0000

    type: int  # H: uint16
    subtype: int  # H: uint16
    unknown1: bytes  # 2s: char x 2
    server_id: int  # H: uint16
    epoch: int  # I: uint32
    unknown2: bytes  # 4s: char x 4
    data: bytes

    def __init__(self, data: bytes, offset: int):
        super().__init__(data, offset)

        self.data = data[offset + self.__class__.DEFINITION.size:]

    @classmethod
    def make(cls, type_: int, subtype: int, server_id: int, epoch: int,
             data: typing.Union[bytes, bytearray, StructBase]):
        return XivMessageIpc(cls.DEFINITION.pack(type_, subtype, b"\0\0", server_id, epoch, b"\0\0\0\0") + bytes(data),
                             0)

    def __bytes__(self):
        return super().__bytes__() + self.data


class XivMessage(StructBase, definition="<IIIH2s"):
    SEGMENT_TYPE_IPC: typing.ClassVar = 3

    length: int  # I: uint32
    source_actor: int  # I: uint32
    target_actor: int  # I: uint32
    segment_type: int  # H: uint16
    unknown1: bytes  # 2s: char x 2

    data: bytes

    def __init__(self, data: bytes, offset: int):
        super().__init__(data, offset)

        if len(data) - offset < self.length:
            raise IncompleteDataException

        self.data = data[offset + self.__class__.DEFINITION.size:offset + self.length]

    @classmethod
    def make(cls, source_actor: int, target_actor: int, segment_type: int,
             data: typing.Union[bytearray, StructBase]):
        data_bytes = bytes(data)
        return XivMessage(cls.DEFINITION.pack(cls.DEFINITION.size + len(data_bytes),
                                              source_actor,
                                              target_actor,
                                              segment_type,
                                              b"\x00\x00") + data_bytes, 0)

    def __bytes__(self):
        res = super().__bytes__() + self.data
        return res


class XivBundle(StructBase, definition="<16sQH2sHHBB6s"):
    MAGIC_CONSTANT_1: typing.ClassVar[bytes] = b"\x52\x52\xa0\x41\xff\x5d\x46\xe2\x7f\x2a\x64\x4d\x7b\x99\xc4\x75"
    MAGIC_CONSTANT_2: typing.ClassVar[bytes] = b"\0" * 16
    MAX_LENGTH: typing.ClassVar[int] = 65536

    magic: bytes  # 16s: char x 16
    timestamp: int  # Q: uint64
    length: int  # H: uint16
    unknown1: bytes  # 2s: char x 2
    conn_type: int  # H: uint16
    message_count: int  # H: uint16
    encoding: int  # B: uint8
    zlib_compressed: int  # B: uint8
    unknown2: bytes  # 6s: char x 6
    messages: typing.List["XivMessage"]

    def __init__(self, data: bytes, offset: int):
        super().__init__(data, offset)

        if self.magic not in (XivBundle.MAGIC_CONSTANT_1, XivBundle.MAGIC_CONSTANT_2):
            raise InvalidDataException

        if self.length > self.__class__.MAX_LENGTH:
            raise InvalidDataException

        if len(data) - offset < self.length:
            raise IncompleteDataException

        msg_data = data[offset + self.__class__.DEFINITION.size:offset + self.length]
        offset += self.__class__.DEFINITION.size

        if self.zlib_compressed:
            try:
                msg_data = zlib.decompress(msg_data)
            except zlib.error:
                raise InvalidDataException
        msg_offset = 0
        self.messages = list()
        for i in range(0, self.message_count):
            try:
                self.messages.append(XivMessage(msg_data, msg_offset))
            except IncompleteDataException:
                raise InvalidDataException
            msg_offset += self.messages[-1].length
            if msg_offset > len(msg_data):
                raise InvalidDataException

    def __bytes__(self):
        data = b"".join(bytes(x) for x in self.messages)
        if self.zlib_compressed:
            data = zlib.compress(data)
        self.length = self.__class__.DEFINITION.size + len(data)
        self.message_count = len(self.messages)
        res = super().__bytes__() + data
        return res

    @classmethod
    def find(cls, data: typing.Union[bytes, bytearray]):
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

            if len(data) < offset + cls.DEFINITION.size:
                break

            try:
                bundle = XivBundle(data, offset)
                offset += bundle.length
                # bundle.length might be modified from this point
                yield bundle
            except IncompleteDataException:
                break
            except InvalidDataException:
                yield data[offset:offset + 1]
                offset += 1
        return offset


@dataclasses.dataclass
class PendingAction:
    action_id: int
    sequence: int
    request_timestamp: float = dataclasses.field(default_factory=time.time)
    response_timestamp: float = 0
    original_wait_time: float = 0
    is_cast: bool = False


class Connection:
    pending_actions: typing.Deque[PendingAction] = collections.deque()
    log_fp: typing.Optional[typing.TextIO] = None
    opcodes: typing.Optional[OpcodeDefinition]

    def __init__(self, sock: socket.socket, source: typing.Tuple[str, int]):
        self.source = source
        self.socket = sock
        self.socket.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
        self.socket.setsockopt(socket.SOL_TCP, socket.TCP_QUICKACK, 1)
        self.socket.setblocking(False)

        self.screen_prefix = f"[{os.getpid():>6}]"
        srv_port, srv_ip = struct.unpack("!2xH4s8x", self.socket.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16))
        self.destination = (socket.inet_ntoa(srv_ip), srv_port)
        self.remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.remote.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
        self.remote.setsockopt(socket.SOL_TCP, socket.TCP_QUICKACK, 1)
        self.remote.setblocking(False)

        self.last_animation_lock_ends_at = 0
        self.last_successful_request = PendingAction(0, 0)

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

            self.log(f"New[{definition.Name}]", self.socket.getsockname(), self.socket.getpeername(),
                     self.destination)
            self.opcodes = definition
            break
        else:
            self.opcodes = None
            self.log(f"New[-]:", self.socket.getsockname(), self.socket.getpeername(), self.destination)

    def source_to_destination(self, bundle: XivBundle):
        for message in bundle.messages:
            if not message.segment_type == XivMessage.SEGMENT_TYPE_IPC:
                continue
            try:
                ipc = XivMessageIpc(message.data, 0)
                if ipc.type != XivMessageIpc.TYPE_INTERESTED:
                    continue
                if self.opcodes.is_request(ipc.subtype):
                    request = XivMessageIpcActionRequest(ipc.data, 0)
                    self.pending_actions.append(PendingAction(request.action_id, request.sequence))

                    # If somehow latest action request has been made before last animation lock end time, keep it.
                    # Otherwise...
                    if self.pending_actions[-1].request_timestamp > self.last_animation_lock_ends_at:

                        # If there was no action queued to begin with before the current one,
                        # update the base lock time to now.
                        if len(self.pending_actions) == 1:
                            self.last_animation_lock_ends_at = self.pending_actions[-1].request_timestamp

                    self.log(f"C2S_ActionRequest: actionId={request.action_id:04x} sequence={request.sequence:04x}")
            except (InvalidDataException, IncompleteDataException):
                continue
        return bundle

    def destination_to_source(self, bundle: XivBundle):
        message_insertions: typing.List[typing.Tuple[int, XivMessage]] = []
        wait_time_dict: typing.Dict[int, float] = {}
        for i, message in enumerate(bundle.messages):
            if not message.segment_type == XivMessage.SEGMENT_TYPE_IPC:
                continue
            if message.source_actor != message.target_actor:
                continue
            try:
                ipc = XivMessageIpc(message.data, 0)
                if (ipc.type == XivMessageIpc.TYPE_CUSTOM
                        and ipc.subtype == XivMessageIpc.SUBTYPE_CUSTOM_ORIGINAL_WAIT_TIME):
                    data = XivMessageIpcCustomOriginalWaitTime(message.data, 0)
                    wait_time_dict[data.source_sequence] = data.original_wait_time
                if ipc.type != XivMessageIpc.TYPE_INTERESTED:
                    continue
                if self.opcodes.is_action_effect(ipc.subtype):
                    effect = XivMessageIpcActionEffect(ipc.data, 0)
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

                    else:
                        while self.pending_actions and self.pending_actions[0].sequence != effect.source_sequence:
                            item = self.pending_actions.popleft()
                            self.log(f"\t┎ ActionRequest ignored for processing: actionId={item.action_id:04x} "
                                     f"sequence={item.sequence:04x}")

                        if self.pending_actions:
                            self.last_successful_request = self.pending_actions.popleft()
                            # 100ms animation lock after cast ends stays.
                            # Modify animation lock duration for instant actions only.
                            # Since no other action is in progress right before the cast ends,
                            # we can safely replace the animation lock with the latest after-cast lock.
                            if not self.last_successful_request.is_cast:
                                self.last_successful_request.response_timestamp = now
                                self.last_successful_request.original_wait_time = original_wait_time

                                tcp_info_c2m = TcpInfo.from_socket(self.socket)
                                tcp_info_m2s = TcpInfo.from_socket(self.remote)
                                if tcp_info_c2m is not None:
                                    extra_message += f"c2m({int(tcp_info_c2m.tcpi_rtt / 1000)}ms) "
                                if tcp_info_m2s is not None:
                                    extra_message += f"m2s({int(tcp_info_m2s.tcpi_rtt / 1000)}ms) "
                                if tcp_info_c2m is None or tcp_info_m2s is None:
                                    extra_delay = EXTRA_DELAY
                                else:
                                    latency = (tcp_info_c2m.tcpi_rtt + tcp_info_m2s.tcpi_rtt) / 1000000.
                                    delay = (self.last_successful_request.response_timestamp
                                             - self.last_successful_request.request_timestamp)
                                    extra_delay = max(0., delay - latency)
                                    extra_delay = min(2 * EXTRA_DELAY, extra_delay)
                                    extra_message += (f"latency={int(latency * 1000)}ms delay={int(delay * 1000)}ms "
                                                      f"extraDelay={int(extra_delay * 1000)}ms")

                                self.last_animation_lock_ends_at += original_wait_time + extra_delay
                                wait_time = self.last_animation_lock_ends_at - now

                    if math.isclose(wait_time, original_wait_time):
                        self.log(f"S2C_ActionEffect: actionId={effect.action_id:04x} "
                                 f"sourceSequence={effect.source_sequence:04x} "
                                 f"wait={int(original_wait_time * 1000)}ms {extra_message}")
                    else:
                        self.log(f"S2C_ActionEffect: actionId={effect.action_id:04x} "
                                 f"sourceSequence={effect.source_sequence:04x} "
                                 f"wait={int(original_wait_time * 1000)}ms->{int(wait_time * 1000)}ms {extra_message}")
                        effect.animation_lock_duration = max(0., wait_time)
                        effect_bytes = bytes(effect)
                        ipc.data = effect_bytes + ipc.data[len(effect_bytes):]
                        ipc_bytes = bytes(ipc)
                        message.data = ipc_bytes + message.data[len(ipc_bytes):]

                        message_insertions.append((
                            i, XivMessage.make(message.source_actor, message.target_actor,
                                               XivMessage.SEGMENT_TYPE_IPC,
                                               XivMessageIpc.make(
                                                   XivMessageIpc.TYPE_CUSTOM,
                                                   XivMessageIpc.SUBTYPE_CUSTOM_ORIGINAL_WAIT_TIME,
                                                   ipc.server_id, ipc.epoch,
                                                   XivMessageIpcCustomOriginalWaitTime.make(effect.source_sequence,
                                                                                            original_wait_time)
                                               ))
                        ))

                elif ipc.subtype == self.opcodes.S2C_ActorControlSelf:
                    control = XivMessageIpcActorControlSelf(ipc.data, 0)
                    if control.category == XivMessageIpcActorControlSelf.CATEGORY_ROLLBACK:
                        action_id = control.param_3
                        source_sequence = control.param_6
                        while (self.pending_actions
                               and (
                                       (source_sequence and self.pending_actions[0].sequence != source_sequence)
                                       or (not source_sequence and self.pending_actions[0].action_id != action_id)
                               )):
                            item = self.pending_actions.popleft()
                            self.log(f"\t┎ ActionRequest ignored for processing: actionId={item.action_id:04x} "
                                     f"sequence={item.sequence:04x}")

                        if self.pending_actions:
                            self.pending_actions.popleft()

                        self.log(f"S2C_ActorControlSelf/ActionRejected: "
                                 f"actionId={action_id:04x} "
                                 f"sourceSequence={source_sequence:08x}")

                elif ipc.subtype == self.opcodes.S2C_ActorControl:
                    control = XivMessageIpcActorControl(ipc.data, 0)
                    if control.category == XivMessageIpcActorControl.CATEGORY_CANCEL_CAST:
                        action_id = control.param_3
                        while self.pending_actions and self.pending_actions[0].action_id != action_id:
                            item = self.pending_actions.popleft()
                            self.log(f"\t┎ ActionRequest ignored for processing: actionId={item.action_id:04x} "
                                     f"sequence={item.sequence:04x}")

                        if self.pending_actions:
                            self.pending_actions.popleft()

                        self.log(f"S2C_ActorControl/CancelCast: actionId={action_id:04x}")

                elif ipc.subtype == self.opcodes.S2C_ActorCast:
                    cast = XivMessageIpcActorCast(ipc.data, 0)

                    # Mark that the last request was a cast.
                    # If it indeed is a cast, the game UI will block the user from generating additional requests,
                    # so first item is guaranteed to be the cast action.
                    if self.pending_actions:
                        self.pending_actions[0].is_cast = True

                    self.log(f"S2C_ActorCast: actionId={cast.action_id:04x} type={cast.skill_type:04x} "
                             f"action_id_2={cast.action_id_2:04x} time={cast.cast_time:.3f} "
                             f"target_id={cast.target_id:08x}")

            except (InvalidDataException, IncompleteDataException):
                continue
        for i, message in reversed(message_insertions):
            bundle.messages.insert(i, message)
        return bundle

    def run(self):
        self.remote.settimeout(3)
        log_path = f"/tmp/xmlm.{datetime.datetime.now():%Y%m%d%H%M%S}.{os.getpid()}.log"
        self.log("Log will be saved to", log_path)
        with open(log_path, "w") as self.log_fp, self.socket, self.remote:
            try:
                self.remote.connect((str(self.destination[0]), self.destination[1]))
                self.remote.settimeout(None)

                check_targets = {
                    self.socket: SocketSet(self.socket, self.remote, "S2D", self.source_to_destination),
                    self.remote: SocketSet(self.remote, self.socket, "D2S", self.destination_to_source),
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
                                self.log(target.log_prefix, "Read finish")
                                target.incoming = None
                                continue

                            if self.opcodes is None:
                                target.outgoing.extend(data)
                            else:
                                target.incoming.extend(data)
                                it = XivBundle.find(target.incoming)
                                while True:
                                    try:
                                        bundle = next(it)
                                    except StopIteration as e:
                                        del target.incoming[0:e.value]
                                        break

                                    if type(bundle) is bytes:
                                        self.log(target.log_prefix, "discarded", " ".join(f"{x:02x}" for x in bundle))
                                        target.outgoing.extend(bundle)
                                    else:
                                        bundle = target.process_function(bundle)
                                        target.outgoing.extend(bytes(bundle))

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
                            self.log(target.log_prefix, "Source read and target write shutdown")
                            try:
                                target.source.shutdown(socket.SHUT_RD)
                            except OSError:
                                pass
                            try:
                                target.target.shutdown(socket.SHUT_WR)
                            except OSError:
                                pass
                self.log("Closed")
            except Exception as e:
                self.log("Closed, exception occurred:", type(e), e)
                return -1
            except KeyboardInterrupt:
                # do no cleanup
                os._exit(0)
            return 0

    def log(self, *msg):
        text = " ".join(str(x) for x in ([datetime.datetime.now(), *msg]))
        try:
            print(self.screen_prefix, text)
        except KeyboardInterrupt:
            pass
        finally:
            if self.log_fp:
                self.log_fp.write(text + "\n")
                self.log_fp.flush()


def load_definitions():
    global definitions
    try:
        with open("definitions.json", "r") as fp:
            definitions = [OpcodeDefinition.from_dict(x) for x in json.load(fp)]
    except Exception:
        definitions_raw = []
        print("Downloading opcode definition files...")
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
        except (requests.HTTPError, ConnectionError, json.JSONDecodeError) as e:
            print(f"Failed to load opcode definition: {e}")
            return -1
        with open("definitions.json", "w") as fp:
            json.dump(definitions_raw, fp)
        definitions = [OpcodeDefinition.from_dict(x) for x in definitions_raw]


def load_rules(port: int) -> typing.Set[str]:
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
    global definitions
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

    load_definitions()

    applied_rules = []
    for rule in load_rules(port):
        if os.system(f"iptables -t nat -I PREROUTING {rule}"):
            for r in applied_rules:
                os.system(f"iptables -t nat -D PREROUTING {r} > /dev/null")
            print("This program requires root permissions.\n")
            return -1
        applied_rules.append(rule)
    os.system("sysctl -w net.ipv4.ip_forward=1")

    listener.listen(8)
    print(f"Listening on {listener.getsockname()}...")
    print("Press Ctrl+C to quit.")

    child_pids = set()

    def on_child_exit(signum, frame):
        if child_pids:
            pid, status = os.waitpid(-1, os.WNOHANG)
            if pid:
                print(f"[{pid:<6}] has exit with status code {status}.")
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
            child_pids.clear()
            listener.close()
            return Connection(sock, source).run()
        sock.close()
        child_pids.add(child_pid)

    for child_pid in child_pids:
        try:
            os.kill(child_pid, signal.SIGINT)
        except OSError:
            pass

    err = False
    for rule in applied_rules:
        if os.system(f"iptables -t nat -D PREROUTING {rule}"):
            print(f"Failed to remove iptables rule: {rule}")
            err = True
    if err:
        return -1
    else:
        print("Cleanup complete.")
        return 0


if __name__ == "__main__":
    exit(__main__())
