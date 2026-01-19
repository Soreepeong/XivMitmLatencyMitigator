import ctypes
import logging
import os
import pathlib
import re
import sys
import typing

from utils.interop.win32 import StdCallFuncType, PeImage, POINTER_SIZE, crt_malloc, crt_free

OodleNetwork1_Shared_Size = StdCallFuncType(ctypes.c_int32, ctypes.c_int32, name="OodleNetwork1_Shared_Size")
OodleNetwork1_Shared_SetWindow = StdCallFuncType(None, ctypes.c_void_p, ctypes.c_int32, ctypes.c_void_p, ctypes.c_int32,
                                                 name="OodleNetwork1_Shared_SetWindow")
OodleNetwork1_Proto_Train = StdCallFuncType(None, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p),
                                            ctypes.POINTER(ctypes.c_int32), ctypes.c_int32,
                                            name="OodleNetwork1_Proto_Train")
OodleNetwork1_Proto_Decode = StdCallFuncType(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                             ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t,
                                             name="OodleNetwork1_Proto_Decode")
OodleNetwork1_Proto_Encode = StdCallFuncType(ctypes.c_int32, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                             ctypes.c_size_t, ctypes.c_void_p, name="OodleNetwork1_Proto_Encode")
OodleNetwork1_Proto_State_Size = StdCallFuncType(ctypes.c_int32, name="OodleNetwork1_Proto_State_Size")
Oodle_Malloc = StdCallFuncType(ctypes.c_size_t, ctypes.c_size_t, ctypes.c_int32, name="Oodle_Malloc")
Oodle_Free = StdCallFuncType(None, ctypes.c_size_t, name="Oodle_Free")
Oodle_SetMallocFree = StdCallFuncType(None, ctypes.c_void_p, ctypes.c_void_p, name="Oodle_SetMallocFree")


def oodle_malloc_impl(size: int, align: int) -> int:
    raw = crt_malloc(size + align + POINTER_SIZE - 1)
    if raw == 0:
        return 0

    aligned = (raw + align + POINTER_SIZE - 1) & ((~align & (sys.maxsize * 2 + 1)) + 1)
    ctypes.c_void_p.from_address(aligned - POINTER_SIZE).value = raw
    return aligned


def oodle_free_impl(aligned: int):
    crt_free(ctypes.c_void_p.from_address(aligned - POINTER_SIZE).value)


class OodleModule:
    def __init__(self, image: PeImage):
        self._image = image

        text = image.section_header(b".text")
        text_view = image.section(text)

        if POINTER_SIZE == 8:
            pattern = br"\x75.\x48\x8d\x15....\x48\x8d\x0d....\xe8(....)\xc6\x05....\x01.{0,256}\x75.\xb9(....)\xe8(....)\x45\x33\xc0\x33\xd2\x48\x8b\xc8\xe8.....{0,6}\x41\xb9(....)\xba.....{0,6}\x48\x8b\xc8\xe8(....)"
        else:
            pattern = br"\x75\x16\x68....\x68....\xe8(....)\xc6\x05....\x01.{0,256}\x75\x27\x6a(.)\xe8(....)\x6a\x00\x6a\x00\x50\xe8....\x83\xc4.\x89\x46.\x68(....)\xff\x76.\x6a.\x50\xe8(....)"
        match = re.search(pattern, text_view, re.DOTALL)
        if not match:
            raise RuntimeError("Could not find InitOodle.")
        self.set_malloc_free_address = image.address.value + image.resolve_rip_relative(
            text.VirtualAddress + match.start(1) - 1)
        self.htbits = int.from_bytes(match.group(2), "little")
        self.shared_size_address = image.address.value + image.resolve_rip_relative(
            text.VirtualAddress + match.start(3) - 1)
        self.window = int.from_bytes(match.group(4), "little")
        self.shared_set_window_address = image.address.value + image.resolve_rip_relative(
            text.VirtualAddress + match.start(5) - 1)

        if POINTER_SIZE == 8:
            pattern = br"\x75\x04\x48\x89..\xe8(....)\x4c..\xe8(....).{0,256}\x01\x75\x0a\x48\x8b.\xe8(....)\xeb\x09\x48\x8b.\x08\xe8(....)"
        else:
            pattern = br"\xe8(....)\x8b\xd8\xe8(....)\x83\x7d\x10\x01.{0,256}\x83\x7d\x10\x01\x6a\x00\x6a\x00\x6a\x00\xff\x77.\x75\x09\xff.\xe8(....)\xeb\x08\xff\x76.\xe8(....)"
        match = re.search(pattern, text_view, re.DOTALL)
        if not match:
            raise RuntimeError("Could not find SetUpStatesAndTrain.")
        self.udp_state_size_address = image.address.value + image.resolve_rip_relative(
            text.VirtualAddress + match.start(1) - 1)
        self.tcp_state_size_address = image.address.value + image.resolve_rip_relative(
            text.VirtualAddress + match.start(2) - 1)
        self.tcp_train_address = image.address.value + image.resolve_rip_relative(
            text.VirtualAddress + match.start(3) - 1)
        self.udp_train_address = image.address.value + image.resolve_rip_relative(
            text.VirtualAddress + match.start(4) - 1)

        if POINTER_SIZE == 8:
            match = re.search(br"\x4d\x85\xd2\x74\x0a\x49\x8b\xca\xe8(....)\xeb\x09\x48\x8b\x49\x08\xe8(....)",
                              text_view, re.DOTALL)
            if not match:
                raise RuntimeError("Could not find Tcp/UdpDecode.")
            self.tcp_decode_address = image.address.value + image.resolve_rip_relative(
                text.VirtualAddress + match.start(1) - 1)
            self.udp_decode_address = image.address.value + image.resolve_rip_relative(
                text.VirtualAddress + match.start(2) - 1)

            match = re.search(
                br"\x48\x85\xc0\x74\x0d\x48\x8b\xc8\xe8(....)\x48..\xeb\x0b\x48\x8b\x49\x08\xe8(....)",
                text_view, re.DOTALL)
            if not match:
                raise RuntimeError("Could not find Tcp/UdpEncode.")
            self.tcp_encode_address = image.address.value + image.resolve_rip_relative(
                text.VirtualAddress + match.start(1) - 1)
            self.udp_encode_address = image.address.value + image.resolve_rip_relative(
                text.VirtualAddress + match.start(2) - 1)
        else:
            pattern = re.compile(br"\x85\xc0\x74.\x50\xe8(....)\x57\x8b\xf0\xff\x15", re.DOTALL)
            match = pattern.search(text_view)
            if not match:
                raise RuntimeError("Could not find TcpEncode.")
            self.tcp_encode_address = image.address.value + image.resolve_rip_relative(
                text.VirtualAddress + match.start(1) - 1)
            match = pattern.search(text_view, match.end())
            if not match:
                raise RuntimeError("Could not find TcpDecode.")
            self.tcp_decode_address = image.address.value + image.resolve_rip_relative(
                text.VirtualAddress + match.start(1) - 1)

            pattern = re.compile(br"\xff\x71\x04\xe8(....)\x57\x8b\xf0\xff\x15", re.DOTALL)
            match = pattern.search(text_view)
            if not match:
                raise RuntimeError("Could not find UdpEncode.")
            self.udp_encode_address = image.address.value + image.resolve_rip_relative(
                text.VirtualAddress + match.start(1) - 1)
            match = pattern.search(text_view, match.end())
            if not match:
                raise RuntimeError("Could not find UdpDecode.")
            self.udp_decode_address = image.address.value + image.resolve_rip_relative(
                text.VirtualAddress + match.start(1) - 1)

        self.set_malloc_free = Oodle_SetMallocFree(self.set_malloc_free_address)
        self.shared_size = OodleNetwork1_Shared_Size(self.shared_size_address)
        self.shared_set_window = OodleNetwork1_Shared_SetWindow(self.shared_set_window_address)
        self.udp_state_size = OodleNetwork1_Proto_State_Size(self.udp_state_size_address)
        self.tcp_state_size = OodleNetwork1_Proto_State_Size(self.tcp_state_size_address)
        self.tcp_train = OodleNetwork1_Proto_Train(self.tcp_train_address)
        self.udp_train = OodleNetwork1_Proto_Train(self.udp_train_address)
        self.tcp_decode = OodleNetwork1_Proto_Decode(self.tcp_decode_address)
        self.udp_decode = OodleNetwork1_Proto_Decode(self.udp_decode_address)
        self.tcp_encode = OodleNetwork1_Proto_Encode(self.tcp_encode_address)
        self.udp_encode = OodleNetwork1_Proto_Encode(self.udp_encode_address)

        if POINTER_SIZE == 8:
            # patch _alloca_probe
            pattern = br"\x48\x83\xec\x10\x4c\x89\x14\x24\x4c\x89\x5c\x24\x08\x4d\x33\xdb"
            match = re.search(pattern, text_view)
            if not match:
                raise RuntimeError("_alloca_probe not found")
            image.view[text.VirtualAddress + match.start(0)] = 0xc3

        else:
            # patch fs register access
            ctypes.memset(self.tcp_train_address + 0xaba - 0xAB0, 0x90, 6)
            ctypes.memset(self.tcp_train_address + 0xad2 - 0xAB0, 0x90, 6)
            ctypes.memset(self.tcp_train_address + 0xbb4 - 0xAB0, 0x90, 7)
            ctypes.memset(self.tcp_train_address + 0xbc8 - 0xAB0, 0x90, 7)

        self._c_oodle_malloc_impl = Oodle_Malloc(oodle_malloc_impl)
        self._c_oodle_free_impl = Oodle_Free(oodle_free_impl)

        self.set_malloc_free(self._c_oodle_malloc_impl.address(), self._c_oodle_free_impl.address())


class OodleInstance:
    def __init__(self, module: OodleModule, use_tcp: bool):
        self._state = (ctypes.c_uint8 * (module.tcp_state_size() if use_tcp else module.udp_state_size()))()
        self._shared = (ctypes.c_uint8 * module.shared_size(module.htbits))()
        self._window = (ctypes.c_uint8 * module.window)()
        module.shared_set_window(
            ctypes.addressof(self._shared), module.htbits,
            ctypes.addressof(self._window), len(self._window))
        (module.tcp_train if use_tcp else module.udp_train)(
            ctypes.addressof(self._state),
            ctypes.addressof(self._shared),
            ctypes.POINTER(ctypes.c_void_p)(),
            ctypes.POINTER(ctypes.c_int32)(),
            0)
        self._encode_function = module.tcp_encode if use_tcp else module.udp_encode
        self._decode_function = module.tcp_decode if use_tcp else module.udp_decode

    def encode(self, src: typing.Union[bytes, bytearray, memoryview]) -> bytearray:
        if not isinstance(src, (bytearray, memoryview)):
            src = bytearray(src)
        enc = bytearray(len(src) + 8)
        del enc[self._encode_function(
            ctypes.addressof(self._state),
            ctypes.addressof(self._shared),
            ctypes.addressof(ctypes.c_byte.from_buffer(src)), len(src),
            ctypes.addressof(ctypes.c_byte.from_buffer(enc))):]
        return enc

    def decode(self, enc: typing.Union[bytes, bytearray, memoryview], result_length: int) -> bytearray:
        dec = bytearray(result_length)
        if not self._decode_function(
                ctypes.addressof(self._state),
                ctypes.addressof(self._shared),
                ctypes.addressof(ctypes.c_byte.from_buffer(enc)), len(enc),
                ctypes.addressof(ctypes.c_byte.from_buffer(dec)), len(dec)):
            raise RuntimeError("Oodle decode fail")
        return dec


class BaseOodleHelper:
    def __enter__(self):
        raise NotImplementedError

    def __exit__(self, exc_type, exc_val, exc_tb):  raise NotImplementedError

    def encode(self, channel: int, data: bytes) -> bytes:
        raise NotImplementedError

    def decode(self, channel: int, data: bytes, declen: int) -> bytes:
        raise NotImplementedError


class OodleWithBudgetAbiThunks(BaseOodleHelper):
    _module: typing.ClassVar[typing.Optional[OodleModule]] = None

    def __init__(self):
        self._channels = {
            0xFFFFFFFF: OodleInstance(self._module, False),
            0: OodleInstance(self._module, True),
            1: OodleInstance(self._module, True),
        }

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def encode(self, channel: int, data: bytes) -> bytes:
        return self._channels[channel].encode(data)

    def decode(self, channel: int, data: bytes, declen: int) -> bytes:
        return self._channels[channel].decode(data, declen)

    @classmethod
    def create(cls, use_tcp: bool) -> OodleInstance:
        return OodleInstance(cls._module, use_tcp)

    @classmethod
    def init_module(cls, path: str):
        ffxiv_exe_filepath = os.path.join(path, "ffxiv.exe")
        ffxiv_dx11_exe_filepath = os.path.join(path, "ffxiv_dx11.exe")
        if POINTER_SIZE == 4:
            if not os.path.exists(ffxiv_exe_filepath):
                raise RuntimeError("Need ffxiv.exe in the same directory. "
                                   "Copy one from your local Windows/Mac installation.")

            cls._module = OodleModule(PeImage(pathlib.Path(ffxiv_exe_filepath).read_bytes()))
        elif POINTER_SIZE == 8:
            if not os.path.exists(ffxiv_dx11_exe_filepath):
                raise RuntimeError("Need ffxiv_dx11.exe in the same directory. "
                                   "Copy one from your local Windows/Mac installation.")

            cls._module = OodleModule(PeImage(pathlib.Path(ffxiv_dx11_exe_filepath).read_bytes()))


OodleHelper = OodleWithBudgetAbiThunks


def test_oodle():
    testval = b'\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x04' * 16
    with OodleHelper() as oodle:
        enc = oodle.encode(0, testval)
        dec = oodle.decode(1, enc, len(testval))
        if testval != dec:
            raise RuntimeError(f"Oodle TCP test failure: {testval.hex()}, {enc.hex()}, {dec.hex()}")
        enc = oodle.encode(0xFFFFFFFF, testval)
        dec = oodle.decode(0xFFFFFFFF, enc, len(testval))
        if testval != dec:
            raise RuntimeError(f"Oodle UDP test failure: {testval.hex()}, {enc.hex()}, {dec.hex()}")
