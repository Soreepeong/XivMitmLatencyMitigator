#!/usr/bin/sudo python

import collections
import dataclasses
import datetime
import ipaddress
import math
import os
import random
import socket
import struct
import threading
import time
import typing
import zlib

ACTION_ID_AUTO_ATTACK = 0x0007
ACTION_ID_AUTO_ATTACK_MCH = 0x0008
AUTO_ATTACK_DELAY = 0.1
SO_ORIGINAL_DST = 80

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

multithread_print_lock = threading.Lock()


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
    def find(cls, data: bytes):
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
                break
            if i != offset:
                yield data[offset:i]
                offset = i

            if len(data) < offset + cls.DEFINITION.size:
                return data[offset:]

            try:
                bundle = XivBundle(data, offset)
                offset += bundle.length
                # bundle.length might be modified from this point
                yield bundle
            except IncompleteDataException:
                return data[offset:]
            except InvalidDataException:
                yield data[offset:offset + 1]
                offset += 1
        return b""


@dataclasses.dataclass
class PendingAction:
    action_id: int
    sequence: int
    request_timestamp: float = dataclasses.field(default_factory=time.time)
    is_cast: bool = False


class Connection:
    all_connections: typing.ClassVar["Connection"] = list()
    pending_actions: typing.Deque[PendingAction] = collections.deque()
    log_fp: typing.Optional[typing.TextIO] = None

    def __init__(self, sock: socket.socket, source: typing.Tuple[str, int]):
        self.source = source
        self.socket = sock

        self.conn_id = self.socket.fileno()
        srv_port, srv_ip = struct.unpack("!2xH4s8x", self.socket.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16))
        self.destination = (socket.inet_ntoa(srv_ip), srv_port)
        self.remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.broken_event = threading.Event()

        self.last_animation_lock_ends_at = 0

        self.is_game_connection = True

        # See: https://github.com/ravahn/machina/tree/NetworkStructs/Machina.FFXIV/Headers/Opcodes
        if any(ipaddress.ip_address(self.destination[0]) in x for x in INTL_DATACENTER_IP_NETWORK):
            self.SUBTYPE_RESPONSE_ACTOR_CAST = 0x02b2
            self.SUBTYPE_RESPONSE_ACTOR_CONTROL = 0x00f0
            self.SUBTYPE_RESPONSE_ACTOR_CONTROL_SELF = 0x017a
            self.SUBTYPE_RESPONSE_ACTION_RESULT = [0x021f, 0x03df, 0x00ad, 0x0229, 0x0197]

            self.SUBTYPE_REQUEST_ACTION = 0x017a

            self.log(f"New[INTL]:", self.socket.getsockname(), self.socket.getpeername(), self.destination)

        elif any(ipaddress.ip_address(self.destination[0]) in x for x in KR_DATACENTER_IP_NETWORK):
            self.SUBTYPE_RESPONSE_ACTOR_CAST = 0x03b8
            self.SUBTYPE_RESPONSE_ACTOR_CONTROL = 0x013d
            self.SUBTYPE_RESPONSE_ACTOR_CONTROL_SELF = 0x025f
            self.SUBTYPE_RESPONSE_ACTION_RESULT = [0x0266, 0x0167, 0x03a7, 0x016b, 0x0231]

            self.SUBTYPE_REQUEST_ACTION = 0x00f0

            self.log(f"New[KR]:", self.socket.getsockname(), self.socket.getpeername(), self.destination)
        else:
            self.is_game_connection = False
            self.log(f"New[-]:", self.socket.getsockname(), self.socket.getpeername(), self.destination)

    def relay(self, read_fn, write_fn, process_fn: typing.Callable[[XivBundle], XivBundle], log_prefix: str):
        try:
            buffer = b""
            more = True
            while more:
                try:
                    data = read_fn(65536)
                except (ConnectionError, socket.timeout, OSError):
                    break
                buffer += data
                if not data:
                    more = False
                if self.is_game_connection:
                    it = XivBundle.find(buffer)
                    while True:
                        try:
                            bundle = next(it)
                        except StopIteration as e:
                            buffer = e.value
                            break

                        if type(bundle) is bytes:
                            self.log(log_prefix, "discarded", " ".join(f"{x:02x}" for x in bundle))
                            data = bundle
                        else:
                            bundle = process_fn(bundle)
                            data = bytes(bundle)
                        try:
                            write_fn(data)
                        except (ConnectionError, socket.timeout, OSError):
                            break
                else:
                    write_fn(buffer)
                    buffer = ""
            if buffer:
                try:
                    write_fn(buffer)
                except (ConnectionError, socket.timeout, OSError):
                    pass
        finally:
            self.broken_event.set()

    def source_to_destination(self, bundle: XivBundle):
        for message in bundle.messages:
            if not message.segment_type == XivMessage.SEGMENT_TYPE_IPC:
                continue
            try:
                ipc = XivMessageIpc(message.data, 0)
                if ipc.type != XivMessageIpc.TYPE_INTERESTED:
                    continue
                if ipc.subtype == self.SUBTYPE_REQUEST_ACTION:
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
                if ipc.subtype in self.SUBTYPE_RESPONSE_ACTION_RESULT:
                    effect = XivMessageIpcActionEffect(ipc.data, 0)
                    original_wait_time = wait_time_dict.get(effect.source_sequence, effect.animation_lock_duration)
                    wait_time = original_wait_time
                    now = time.time()

                    if effect.source_sequence == 0:
                        if effect.action_id in (ACTION_ID_AUTO_ATTACK, ACTION_ID_AUTO_ATTACK_MCH):
                            if self.last_animation_lock_ends_at > now:
                                # if animation lock is supposedly already in progress,
                                # add the new value to previously in-progress animation lock, instead of replacing it.
                                self.last_animation_lock_ends_at += AUTO_ATTACK_DELAY
                                wait_time = self.last_animation_lock_ends_at - now

                            else:
                                # even if it wasn't, the server would consider other actions in progress when
                                # calculating auto-attack delay, so we fix it to 100ms.
                                wait_time = AUTO_ATTACK_DELAY
                        else:
                            self.log(f"\t┎ Not user-originated, and isn't an auto-attack ({effect.action_id:04x})")

                    else:
                        while self.pending_actions and self.pending_actions[0].sequence != effect.source_sequence:
                            item = self.pending_actions.popleft()
                            self.log(f"\t┎ ActionRequest ignored for processing: actionId={item.action_id:04x} "
                                     f"sequence={item.sequence:04x}")

                        if self.pending_actions:
                            item = self.pending_actions.popleft()
                            # 100ms animation lock after cast ends stays.
                            # Modify animation lock duration for instant actions only.
                            # Since no other action is in progress right before the cast ends,
                            # we can safely replace the animation lock with the latest after-cast lock.
                            if not item.is_cast:
                                self.last_animation_lock_ends_at += original_wait_time + EXTRA_DELAY
                                wait_time = self.last_animation_lock_ends_at - now

                    if math.isclose(wait_time, original_wait_time):
                        self.log(f"S2C_ActionEffect: actionId={effect.action_id:04x} "
                                 f"sourceSequence={effect.source_sequence:04x} "
                                 f"wait={int(original_wait_time * 1000)}ms")
                    else:
                        self.log(f"S2C_ActionEffect: actionId={effect.action_id:04x} "
                                 f"sourceSequence={effect.source_sequence:04x} "
                                 f"wait={int(original_wait_time * 1000)}ms->{int(wait_time * 1000)}ms")
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

                elif ipc.subtype == self.SUBTYPE_RESPONSE_ACTOR_CONTROL_SELF:
                    control = XivMessageIpcActorControlSelf(ipc.data, 0)
                    if control.category == XivMessageIpcActorControlSelf.CATEGORY_ROLLBACK:
                        source_sequence = control.param_5
                        while self.pending_actions and self.pending_actions[0].sequence != source_sequence:
                            item = self.pending_actions.popleft()
                            self.log(f"\t┎ ActionRequest ignored for processing: actionId={item.action_id:04x} "
                                     f"sequence={source_sequence:04x}")

                        if self.pending_actions:
                            self.pending_actions.popleft()

                        self.log(f"S2C_ActorControlSelf/ActionRejected: "
                                 f"actionId={control.param_2:04x}"
                                 f"sourceSequence={source_sequence:08x}")

                elif ipc.subtype == self.SUBTYPE_RESPONSE_ACTOR_CONTROL:
                    control = XivMessageIpcActorControl(ipc.data, 0)
                    if control.category == XivMessageIpcActorControl.CATEGORY_CANCEL_CAST:
                        if self.pending_actions:
                            self.pending_actions.popleft()

                        self.log(f"S2C_ActorControl/CancelCast: "
                                 f"p1={control.param_1:08x} "
                                 f"action={control.param_2:04x}"
                                 f"p3={control.param_3:08x} "
                                 f"p4={control.param_4:08x} ")

                elif ipc.subtype == self.SUBTYPE_RESPONSE_ACTOR_CAST:
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
        threads = []
        log_path = f"/tmp/xmlm.{datetime.datetime.now():%Y%m%d%H%M%S}.{self.conn_id}.log"
        self.log("Log will be saved to", log_path)
        with open(log_path, "w") as self.log_fp:
            try:
                try:
                    self.remote.connect(self.destination)
                except (ConnectionError, socket.timeout):
                    return
                self.remote.settimeout(60)

                threads.append(threading.Thread(target=self.relay, args=(self.socket.recv,
                                                                         self.remote.send,
                                                                         self.source_to_destination,
                                                                         "S2D")))
                threads.append(threading.Thread(target=self.relay, args=(self.remote.recv,
                                                                         self.socket.send,
                                                                         self.destination_to_source,
                                                                         "D2S")))
                for x in threads:
                    x.start()
                self.broken_event.wait()
            finally:
                self.remote.close()
                self.socket.close()
                for x in threads:
                    x.join()
                self.log("Closed")
                Connection.all_connections.remove(self)

    def log(self, *msg):
        with multithread_print_lock:
            text = " ".join(str(x) for x in ([datetime.datetime.now(), *msg]))
            print(f"[{self.conn_id}]", text)
            if self.log_fp:
                self.log_fp.write(text + "\n")
                self.log_fp.flush()


def __main__() -> int:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    while True:
        port = random.randint(10000, 65535)
        try:
            listener.bind(("0.0.0.0", port))
        except OSError:
            continue
        break

    networks = ",".join(str(x) for x in INTL_DATACENTER_IP_NETWORK.union(KR_DATACENTER_IP_NETWORK))
    if os.system(f"iptables -t nat -I PREROUTING -d {networks} -p tcp -j REDIRECT --to {port}"):
        print("This program requires root permissions.\n")
        return -1
    os.system("sysctl -w net.ipv4.ip_forward=1")

    listener.listen(8)
    print(f"Listening on {listener.getsockname()}...")
    print("Press Ctrl+C to quit.")
    try:
        while True:
            try:
                connection = Connection(*listener.accept())
            except KeyboardInterrupt as e:
                break
            Connection.all_connections.append(connection)
            threading.Thread(target=connection.run).start()
        for x in list(Connection.all_connections):
            x.broken_event.set()
        for x in list(Connection.all_connections):
            x.join()
    finally:
        if os.system(f"iptables -t nat -D PREROUTING -d {networks} -p tcp -j REDIRECT --to-port {port}"):
            print("Failed to remove iptables rule.")
            return -1
        else:
            print("Cleanup complete.")
            return 0


if __name__ == "__main__":
    exit(__main__())
