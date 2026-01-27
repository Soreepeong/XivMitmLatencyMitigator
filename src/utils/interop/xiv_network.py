import ctypes
import enum
import typing


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


class XivMessageIpcActionRequestCommon(ctypes.LittleEndianStructure):
    _fields_ = (
        ("action_id", ctypes.c_uint32),
        ("unknown_0x002", ctypes.c_uint16),
        ("sequence", ctypes.c_uint16),
    )

    action_id: typing.Union[int, ctypes.c_uint32]
    sequence: typing.Union[int, ctypes.c_uint16]


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
        ("compression", ctypes.c_uint8),
        ("unknown_0x022", ctypes.c_uint16),
        ("decoded_body_length", ctypes.c_uint32),
    )

    magic: typing.Union[bytearray, ctypes.c_byte * 16]
    timestamp: typing.Union[int, ctypes.c_uint64]
    length: typing.Union[int, ctypes.c_uint32]
    conn_type: typing.Union[int, ctypes.c_uint16]
    message_count: typing.Union[int, ctypes.c_uint16]
    encoding: typing.Union[int, ctypes.c_uint8]
    compression: typing.Union[int, ctypes.c_uint8]
    unknown_0x022: typing.Union[int, ctypes.c_uint16]
    decoded_body_length: typing.Union[int, ctypes.c_uint32]

    @classmethod
    def is_xiv_bundle(cls, buf: memoryview):
        check_len = min(len(cls.MAGIC_CONSTANT_1), len(buf))
        if (cls.MAGIC_CONSTANT_1[:check_len] != buf[:check_len] and
                cls.MAGIC_CONSTANT_2[:check_len] != buf[:check_len]):
            return False
        if check_len != len(cls.MAGIC_CONSTANT_1):
            return None

        header = cls.from_buffer(buf)
        if header.length > cls.MAX_LENGTH:
            return False
        if header.compression not in (0, 1, 2):
            return False
        if header.length > len(buf):
            return None

        return True
