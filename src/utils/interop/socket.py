import ctypes
import sys


class sockaddr_in(ctypes.BigEndianStructure):
    _fields_ = [
        ("sin_family", ctypes.c_uint16),
        ("sin_port", ctypes.c_uint16),
        ("sin_addr", ctypes.c_byte * 4),
        ("sin_zero", ctypes.c_byte * 8)
    ]

    sin_family: ctypes.c_uint16
    sin_port: ctypes.c_uint16
    sin_addr: ctypes.c_byte * 4
    sin_zero: ctypes.c_byte * 8


class sockaddr_in6(ctypes.BigEndianStructure):
    _fields_ = [
        ("sin6_family", ctypes.c_int16),
        ("sin6_port", ctypes.c_uint16),
        ("sin6_flowinfo", ctypes.c_uint32),
        ("sin6_addr", ctypes.c_byte * 16),
        ("_sin6_scope_id", ctypes.c_byte * 4),
    ]

    sin6_family: ctypes.c_uint16
    sin6_port: ctypes.c_uint16
    sin6_flowinfo: ctypes.c_uint32
    sin6_addr: ctypes.c_byte * 4
    _sin6_scope_id: bytes | ctypes.c_byte * 4

    @property
    def sin6_scope_id(self):
        return int.from_bytes(self._sin6_scope_id, sys.byteorder, signed=False)

    @sin6_scope_id.setter
    def sin6_scope_id(self, val: int):
        self._sin6_scope_id = val.to_bytes(4, sys.byteorder, signed=False)
