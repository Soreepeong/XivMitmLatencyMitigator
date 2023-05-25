#!/usr/bin/sudo python
import argparse
import collections
import contextlib
import ctypes
import ctypes.util
import dataclasses
import datetime
import enum
import errno
import io
import ipaddress
import json
import logging.handlers
import os
import pathlib
import random
import re
import signal
import socket
import struct
import sys
import time
import typing
import urllib.request

import math
import mmap
import select
import zlib

# region Miscellaneous constants and typedefs

ACTION_ID_AUTO_ATTACK = 0x0007
ACTION_ID_AUTO_ATTACK_MCH = 0x0008
AUTO_ATTACK_DELAY = 0.1
SO_ORIGINAL_DST = 80
OPCODE_DEFINITION_LIST_URL = "https://api.github.com/repos/Soreepeong/XivAlexander/contents/StaticData/OpcodeDefinition"

EXTRA_DELAY_HELP = """Server responses have been usually taking between 50ms and 100ms on below-1ms latency to server, so 75ms is a good average.
The server will do sanity check on the frequency of action use requests,
and it's very easy to identify whether you're trying to go below allowed minimum value.
This addon is already in gray area. Do NOT decrease this value. You've been warned.
Feel free to increase and see how does it feel like to play on high latency instead, though."""

T = typing.TypeVar("T")
ArgumentTuple = collections.namedtuple("ArgumentTuple", ("region", "extra_delay", "measure_ping", "update_opcodes"))


def clamp(v: T, min_: T, max_: T) -> T:
    return max(min_, min(max_, v))


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


# endregion

# region PE Structures

IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16
IMAGE_DIRECTORY_ENTRY_BASERELOC = 5
IMAGE_SIZEOF_SHORT_NAME = 8


class ImageDosHeader(ctypes.LittleEndianStructure):
    _fields_ = (
        ("e_magic", ctypes.c_uint16),
        ("e_cblp", ctypes.c_uint16),
        ("e_cp", ctypes.c_uint16),
        ("e_crlc", ctypes.c_uint16),
        ("e_cparhdr", ctypes.c_uint16),
        ("e_minalloc", ctypes.c_uint16),
        ("e_maxalloc", ctypes.c_uint16),
        ("e_ss", ctypes.c_uint16),
        ("e_sp", ctypes.c_uint16),
        ("e_csum", ctypes.c_uint16),
        ("e_ip", ctypes.c_uint16),
        ("e_cs", ctypes.c_uint16),
        ("e_lfarlc", ctypes.c_uint16),
        ("e_ovno", ctypes.c_uint16),
        ("e_res", ctypes.c_uint16 * 4),
        ("e_oemid", ctypes.c_uint16),
        ("e_oeminfo", ctypes.c_uint16),
        ("e_res2", ctypes.c_uint16 * 10),
        ("e_lfanew", ctypes.c_uint32),
    )
    e_magic: typing.Union[int, ctypes.c_uint16]
    e_cblp: typing.Union[int, ctypes.c_uint16]
    e_cp: typing.Union[int, ctypes.c_uint16]
    e_crlc: typing.Union[int, ctypes.c_uint16]
    e_cparhdr: typing.Union[int, ctypes.c_uint16]
    e_minalloc: typing.Union[int, ctypes.c_uint16]
    e_maxalloc: typing.Union[int, ctypes.c_uint16]
    e_ss: typing.Union[int, ctypes.c_uint16]
    e_sp: typing.Union[int, ctypes.c_uint16]
    e_csum: typing.Union[int, ctypes.c_uint16]
    e_ip: typing.Union[int, ctypes.c_uint16]
    e_cs: typing.Union[int, ctypes.c_uint16]
    e_lfarlc: typing.Union[int, ctypes.c_uint16]
    e_ovno: typing.Union[int, ctypes.c_uint16]
    e_res: typing.Union[typing.Sequence[int], ctypes.c_uint16 * 4]
    e_oemid: typing.Union[int, ctypes.c_uint16]
    e_oeminfo: typing.Union[int, ctypes.c_uint16]
    e_res2: typing.Union[typing.Sequence[int], ctypes.c_uint16 * 10]
    e_lfanew: typing.Union[int, ctypes.c_uint32]


class ImageFileHeader(ctypes.LittleEndianStructure):
    _fields_ = (
        ("Machine", ctypes.c_uint16),
        ("NumberOfSections", ctypes.c_uint16),
        ("TimeDateStamp", ctypes.c_uint32),
        ("PointerToSymbolTable", ctypes.c_uint32),
        ("NumberOfSymbols", ctypes.c_uint32),
        ("SizeOfOptionalHeader", ctypes.c_uint16),
        ("Characteristics", ctypes.c_uint16),
    )
    Machine: typing.Union[int, ctypes.c_uint16]
    NumberOfSections: typing.Union[int, ctypes.c_uint16]
    TimeDateStamp: typing.Union[int, ctypes.c_uint32]
    PointerToSymbolTable: typing.Union[int, ctypes.c_uint32]
    NumberOfSymbols: typing.Union[int, ctypes.c_uint32]
    SizeOfOptionalHeader: typing.Union[int, ctypes.c_uint16]
    Characteristics: typing.Union[int, ctypes.c_uint16]


class ImageDataDirectory(ctypes.LittleEndianStructure):
    _fields_ = (
        ("VirtualAddress", ctypes.c_uint32),
        ("Size", ctypes.c_uint32),
    )
    VirtualAddress: typing.Union[int, ctypes.c_uint32]
    Size: typing.Union[int, ctypes.c_uint32]


class ImageOptionalHeader32(ctypes.LittleEndianStructure):
    _fields_ = (
        ("Magic", ctypes.c_uint16),
        ("MajorLinkerVersion", ctypes.c_uint8),
        ("MinorLinkerVersion", ctypes.c_uint8),
        ("SizeOfCode", ctypes.c_uint32),
        ("SizeOfInitializedData", ctypes.c_uint32),
        ("SizeOfUninitializedData", ctypes.c_uint32),
        ("AddressOfEntryPoint", ctypes.c_uint32),
        ("BaseOfCode", ctypes.c_uint32),
        ("BaseOfData", ctypes.c_uint32),
        ("ImageBase", ctypes.c_uint32),
        ("SectionAlignment", ctypes.c_uint32),
        ("FileAlignment", ctypes.c_uint32),
        ("MajorOperatingSystemVersion", ctypes.c_uint16),
        ("MinorOperatingSystemVersion", ctypes.c_uint16),
        ("MajorImageVersion", ctypes.c_uint16),
        ("MinorImageVersion", ctypes.c_uint16),
        ("MajorSubsystemVersion", ctypes.c_uint16),
        ("MinorSubsystemVersion", ctypes.c_uint16),
        ("Win32VersionValue", ctypes.c_uint32),
        ("SizeOfImage", ctypes.c_uint32),
        ("SizeOfHeaders", ctypes.c_uint32),
        ("CheckSum", ctypes.c_uint32),
        ("Subsystem", ctypes.c_uint16),
        ("DllCharacteristics", ctypes.c_uint16),
        ("SizeOfStackReserve", ctypes.c_uint32),
        ("SizeOfStackCommit", ctypes.c_uint32),
        ("SizeOfHeapReserve", ctypes.c_uint32),
        ("SizeOfHeapCommit", ctypes.c_uint32),
        ("LoaderFlags", ctypes.c_uint32),
        ("NumberOfRvaAndSizes", ctypes.c_uint32),
        ("DataDirectory", ImageDataDirectory * IMAGE_NUMBEROF_DIRECTORY_ENTRIES),
    )
    Magic: typing.Union[int, ctypes.c_uint16]
    MajorLinkerVersion: typing.Union[int, ctypes.c_uint8]
    MinorLinkerVersion: typing.Union[int, ctypes.c_uint8]
    SizeOfCode: typing.Union[int, ctypes.c_uint32]
    SizeOfInitializedData: typing.Union[int, ctypes.c_uint32]
    SizeOfUninitializedData: typing.Union[int, ctypes.c_uint32]
    AddressOfEntryPoint: typing.Union[int, ctypes.c_uint32]
    BaseOfCode: typing.Union[int, ctypes.c_uint32]
    BaseOfData: typing.Union[int, ctypes.c_uint32]
    ImageBase: typing.Union[int, ctypes.c_uint32]
    SectionAlignment: typing.Union[int, ctypes.c_uint32]
    FileAlignment: typing.Union[int, ctypes.c_uint32]
    MajorOperatingSystemVersion: typing.Union[int, ctypes.c_uint16]
    MinorOperatingSystemVersion: typing.Union[int, ctypes.c_uint16]
    MajorImageVersion: typing.Union[int, ctypes.c_uint16]
    MinorImageVersion: typing.Union[int, ctypes.c_uint16]
    MajorSubsystemVersion: typing.Union[int, ctypes.c_uint16]
    MinorSubsystemVersion: typing.Union[int, ctypes.c_uint16]
    Win32VersionValue: typing.Union[int, ctypes.c_uint32]
    SizeOfImage: typing.Union[int, ctypes.c_uint32]
    SizeOfHeaders: typing.Union[int, ctypes.c_uint32]
    CheckSum: typing.Union[int, ctypes.c_uint32]
    Subsystem: typing.Union[int, ctypes.c_uint16]
    DllCharacteristics: typing.Union[int, ctypes.c_uint16]
    SizeOfStackReserve: typing.Union[int, ctypes.c_uint32]
    SizeOfStackCommit: typing.Union[int, ctypes.c_uint32]
    SizeOfHeapReserve: typing.Union[int, ctypes.c_uint32]
    SizeOfHeapCommit: typing.Union[int, ctypes.c_uint32]
    LoaderFlags: typing.Union[int, ctypes.c_uint32]
    NumberOfRvaAndSizes: typing.Union[int, ctypes.c_uint32]
    DataDirectory: typing.Union[typing.Sequence[ImageDataDirectory], ImageDataDirectory * IMAGE_NUMBEROF_DIRECTORY_ENTRIES]


class ImageOptionalHeader64(ctypes.LittleEndianStructure):
    _fields_ = (
        ("Magic", ctypes.c_uint16),
        ("MajorLinkerVersion", ctypes.c_uint8),
        ("MinorLinkerVersion", ctypes.c_uint8),
        ("SizeOfCode", ctypes.c_uint32),
        ("SizeOfInitializedData", ctypes.c_uint32),
        ("SizeOfUninitializedData", ctypes.c_uint32),
        ("AddressOfEntryPoint", ctypes.c_uint32),
        ("BaseOfCode", ctypes.c_uint32),
        ("ImageBase", ctypes.c_uint64),
        ("SectionAlignment", ctypes.c_uint32),
        ("FileAlignment", ctypes.c_uint32),
        ("MajorOperatingSystemVersion", ctypes.c_uint16),
        ("MinorOperatingSystemVersion", ctypes.c_uint16),
        ("MajorImageVersion", ctypes.c_uint16),
        ("MinorImageVersion", ctypes.c_uint16),
        ("MajorSubsystemVersion", ctypes.c_uint16),
        ("MinorSubsystemVersion", ctypes.c_uint16),
        ("Win32VersionValue", ctypes.c_uint32),
        ("SizeOfImage", ctypes.c_uint32),
        ("SizeOfHeaders", ctypes.c_uint32),
        ("CheckSum", ctypes.c_uint32),
        ("Subsystem", ctypes.c_uint16),
        ("DllCharacteristics", ctypes.c_uint16),
        ("SizeOfStackReserve", ctypes.c_uint64),
        ("SizeOfStackCommit", ctypes.c_uint64),
        ("SizeOfHeapReserve", ctypes.c_uint64),
        ("SizeOfHeapCommit", ctypes.c_uint64),
        ("LoaderFlags", ctypes.c_uint32),
        ("NumberOfRvaAndSizes", ctypes.c_uint32),
        ("DataDirectory", ImageDataDirectory * IMAGE_NUMBEROF_DIRECTORY_ENTRIES),
    )
    Magic: typing.Union[int, ctypes.c_uint16]
    MajorLinkerVersion: typing.Union[int, ctypes.c_uint8]
    MinorLinkerVersion: typing.Union[int, ctypes.c_uint8]
    SizeOfCode: typing.Union[int, ctypes.c_uint32]
    SizeOfInitializedData: typing.Union[int, ctypes.c_uint32]
    SizeOfUninitializedData: typing.Union[int, ctypes.c_uint32]
    AddressOfEntryPoint: typing.Union[int, ctypes.c_uint32]
    BaseOfCode: typing.Union[int, ctypes.c_uint32]
    ImageBase: typing.Union[int, ctypes.c_uint64]
    SectionAlignment: typing.Union[int, ctypes.c_uint32]
    FileAlignment: typing.Union[int, ctypes.c_uint32]
    MajorOperatingSystemVersion: typing.Union[int, ctypes.c_uint16]
    MinorOperatingSystemVersion: typing.Union[int, ctypes.c_uint16]
    MajorImageVersion: typing.Union[int, ctypes.c_uint16]
    MinorImageVersion: typing.Union[int, ctypes.c_uint16]
    MajorSubsystemVersion: typing.Union[int, ctypes.c_uint16]
    MinorSubsystemVersion: typing.Union[int, ctypes.c_uint16]
    Win32VersionValue: typing.Union[int, ctypes.c_uint32]
    SizeOfImage: typing.Union[int, ctypes.c_uint32]
    SizeOfHeaders: typing.Union[int, ctypes.c_uint32]
    CheckSum: typing.Union[int, ctypes.c_uint32]
    Subsystem: typing.Union[int, ctypes.c_uint16]
    DllCharacteristics: typing.Union[int, ctypes.c_uint16]
    SizeOfStackReserve: typing.Union[int, ctypes.c_uint64]
    SizeOfStackCommit: typing.Union[int, ctypes.c_uint64]
    SizeOfHeapReserve: typing.Union[int, ctypes.c_uint64]
    SizeOfHeapCommit: typing.Union[int, ctypes.c_uint64]
    LoaderFlags: typing.Union[int, ctypes.c_uint32]
    NumberOfRvaAndSizes: typing.Union[int, ctypes.c_uint32]
    DataDirectory: typing.Union[typing.Sequence[ImageDataDirectory], ImageDataDirectory * IMAGE_NUMBEROF_DIRECTORY_ENTRIES]


class ImageNtHeaders32(ctypes.LittleEndianStructure):
    _fields_ = (
        ("Signature", ctypes.c_uint32),
        ("FileHeader", ImageFileHeader),
        ("OptionalHeader", ImageOptionalHeader32),
    )
    Signature: typing.Union[int, ctypes.c_uint32]
    FileHeader: ImageFileHeader
    OptionalHeader: ImageOptionalHeader32


class ImageNtHeaders64(ctypes.LittleEndianStructure):
    _fields_ = (
        ("Signature", ctypes.c_uint32),
        ("FileHeader", ImageFileHeader),
        ("OptionalHeader", ImageOptionalHeader64),
    )
    Signature: typing.Union[int, ctypes.c_uint32]
    FileHeader: ImageFileHeader
    OptionalHeader: ImageOptionalHeader64


class ImageSectionHeader(ctypes.LittleEndianStructure):
    _fields_ = (
        ("Name", ctypes.c_char * IMAGE_SIZEOF_SHORT_NAME),
        ("VirtualSize", ctypes.c_uint32),
        ("VirtualAddress", ctypes.c_uint32),
        ("SizeOfRawData", ctypes.c_uint32),
        ("PointerToRawData", ctypes.c_uint32),
        ("PointerToRelocations", ctypes.c_uint32),
        ("PointerToLinenumbers", ctypes.c_uint32),
        ("NumberOfRelocations", ctypes.c_uint16),
        ("NumberOfLinenumbers", ctypes.c_uint16),
        ("Characteristics", ctypes.c_uint32),
    )
    Name: typing.Union[bytes, ctypes.c_char * IMAGE_SIZEOF_SHORT_NAME]
    VirtualSize: typing.Union[int, ctypes.c_uint32]
    VirtualAddress: typing.Union[int, ctypes.c_uint32]
    SizeOfRawData: typing.Union[int, ctypes.c_uint32]
    PointerToRawData: typing.Union[int, ctypes.c_uint32]
    PointerToRelocations: typing.Union[int, ctypes.c_uint32]
    PointerToLinenumbers: typing.Union[int, ctypes.c_uint32]
    NumberOfRelocations: typing.Union[int, ctypes.c_uint16]
    NumberOfLinenumbers: typing.Union[int, ctypes.c_uint16]
    Characteristics: typing.Union[int, ctypes.c_uint32]


class ImageBaseRelocation(ctypes.LittleEndianStructure):
    _fields_ = (
        ("VirtualAddress", ctypes.c_uint32),
        ("SizeOfBlock", ctypes.c_uint32),
    )
    VirtualAddress: typing.Union[int, ctypes.c_uint32]
    SizeOfBlock: typing.Union[int, ctypes.c_uint32]


# endregion

# region x86/x64-specific system ffi definitions

POINTER_SIZE = ctypes.sizeof(ctypes.c_void_p)
if os.name == 'nt':
    crt_malloc = ctypes.cdll.msvcrt.malloc
    crt_free = ctypes.cdll.msvcrt.free


    def allocate_executable_memory(length: int):
        virtualalloc = ctypes.windll.kernel32.VirtualAlloc
        virtualalloc.argtypes = (ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_uint32)
        virtualalloc.restype = ctypes.c_void_p
        return ctypes.c_void_p(virtualalloc(0,
                                            length,
                                            0x3000,  # MEM_RESERVE | MEM_COMMIT
                                            0x40))  # PAGE_EXECUTE_READWRITE


    def free_executable_memory(ptr: ctypes.c_void_p):
        ctypes.windll.kernel32.VirtualFree(ptr, 0, 0x8000)
else:
    libc = ctypes.CDLL(ctypes.util.find_library("c"))
    crt_malloc = libc.malloc
    crt_free = libc.free

    # close enough definitions
    libc.memalign.argtypes = ctypes.c_size_t, ctypes.c_size_t
    libc.memalign.restype = ctypes.c_size_t
    libc.mprotect.argtypes = ctypes.c_size_t, ctypes.c_size_t, ctypes.c_size_t


    def allocate_executable_memory(length: int):
        p = libc.memalign(mmap.PAGESIZE, length)
        libc.mprotect(p, length, mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
        return ctypes.c_void_p(p)


    def free_executable_memory(ptr: ctypes.c_void_p):
        crt_free(ptr.value)

crt_malloc.argtypes = (ctypes.c_size_t,)
crt_malloc.restype = ctypes.c_size_t
crt_free.argtypes = (ctypes.c_size_t,)

PyMemoryView_FromMemory = ctypes.pythonapi.PyMemoryView_FromMemory
PyMemoryView_FromMemory.argtypes = (ctypes.c_void_p, ctypes.c_ssize_t, ctypes.c_int)
PyMemoryView_FromMemory.restype = ctypes.py_object


# endregion

# region budget windows stdcall <-> linux cdecl ABI converters

class PeImage:
    def __init__(self, data: typing.Union[bytearray, bytes]):
        self._data = data if isinstance(data, bytearray) else bytearray(data)

        self.dos = ImageDosHeader.from_buffer(self._data, 0)
        if self.dos.e_magic != 0x5a4d:
            raise ValueError("bad dos header")

        if POINTER_SIZE == 8:
            self.nt = ImageNtHeaders64.from_buffer(self._data, self.dos.e_lfanew)
        else:
            self.nt = ImageNtHeaders32.from_buffer(self._data, self.dos.e_lfanew)
        if self.nt.Signature != 0x4550:
            raise ValueError("bad nt header")

        self.sections: typing.Union[typing.Sequence[ImageSectionHeader], ctypes.Array[ImageSectionHeader]] = (
                ImageSectionHeader * self.nt.FileHeader.NumberOfSections).from_buffer(
            self._data, self.dos.e_lfanew + ctypes.sizeof(self.nt))

        self.address: ctypes.c_void_p = allocate_executable_memory(self.nt.OptionalHeader.SizeOfImage)
        self.view: memoryview = PyMemoryView_FromMemory(
            self.address,
            self.nt.OptionalHeader.SizeOfImage,
            0x200,  # Read/Write
        )

        self._map_headers_and_sections()
        self._relocate()

    def _map_headers_and_sections(self):
        ctypes.memmove(self.address,
                       ctypes.addressof(ctypes.c_byte.from_buffer(self._data)),
                       self.nt.OptionalHeader.SizeOfHeaders)
        for shdr in self.sections:
            ctypes.memmove(ctypes.addressof(ctypes.c_byte.from_buffer(self.view, shdr.VirtualAddress)),
                           ctypes.addressof(ctypes.c_byte.from_buffer(self._data, shdr.PointerToRawData)),
                           min(shdr.SizeOfRawData, shdr.VirtualSize))

    def _relocate(self):
        rva = int(self.nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress)
        rva_to = rva + int(self.nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
        displacement = self.address.value - self.nt.OptionalHeader.ImageBase
        while rva < rva_to:
            page = ctypes.cast(ctypes.c_void_p(self.address.value + rva), ctypes.POINTER(ImageBaseRelocation)).contents
            page_data = ctypes.cast(ctypes.c_void_p(self.address.value + rva + ctypes.sizeof(page)),
                                    ctypes.POINTER(ctypes.c_uint16 * ((page.SizeOfBlock - ctypes.sizeof(page)) // 2))
                                    ).contents
            for relo in page_data:
                absptr_address = self.address.value + page.VirtualAddress + (relo & 0xFFF)
                if relo >> 12 == 0:
                    pass
                elif relo >> 12 == 3:
                    ptr = ctypes.cast(absptr_address, ctypes.POINTER(ctypes.c_uint32))
                    ctypes.memmove(absptr_address,
                                   ctypes.addressof(ctypes.c_uint32(ptr.contents.value + displacement)), 4)
                elif relo >> 12 == 10:
                    ptr = ctypes.cast(absptr_address, ctypes.POINTER(ctypes.c_uint64))
                    ctypes.memmove(absptr_address,
                                   ctypes.addressof(ctypes.c_uint64(ptr.contents.value + displacement)), 8)
                else:
                    raise RuntimeError("Unsupported relocation type")
            rva += page.SizeOfBlock

    def section_header(self, name: bytes):
        try:
            return next(s for s in self.sections if s.Name == name)
        except StopIteration:
            return KeyError

    def section(self, section: typing.Union[bytes, ImageSectionHeader]) -> memoryview:
        if not isinstance(section, ImageSectionHeader):
            section = self.section_header(section)
        return self.view[section.VirtualAddress:section.VirtualAddress + section.VirtualSize]

    def resolve_rip_relative(self, addr: int):
        if self.view[addr] in (0xE8, 0xE9):
            return addr + 5 + int.from_bytes(self.view[addr + 1:addr + 5], "little", signed=True)
        else:
            raise NotImplementedError


class StdCallFunc32ByPythonFunction:
    def __init__(self, pyctypefn, fn: callable, arglen: int, name: str):
        self._inner = pyctypefn(fn)
        self._fn = fn
        self._name = name
        inner_address = ctypes.cast(self._inner, ctypes.c_void_p)

        codelen = 1 + arglen // 4 * 7 + 5 + 2 + 6 + 3
        codeptr = allocate_executable_memory(codelen)
        buf = (ctypes.c_uint8 * codelen).from_address(codeptr.value)
        buf[0] = 0x90
        i = 1
        for j in range(0, arglen, 4):
            buf[i] = 0xff
            buf[i + 1] = 0xb4
            buf[i + 2] = 0x24
            ctypes.c_uint32.from_address(codeptr.value + i + 3).value = arglen
            i += 7

        buf[i] = 0xb8
        ctypes.c_void_p.from_address(codeptr.value + i + 1).value = inner_address.value
        i += 5

        buf[i] = 0xff
        buf[i + 1] = 0xd0
        i += 2

        buf[i + 0] = 0x81
        buf[i + 1] = 0xc4
        ctypes.c_uint32.from_address(codeptr.value + i + 2).value = arglen
        i += 6

        buf[i] = 0xc2
        ctypes.c_uint16.from_address(codeptr.value + i + 1).value = arglen

        self._address = codeptr

    def address(self):
        return self._address

    def __call__(self, *args):
        return self._fn(*args)


class StdCallFunc64ByPythonFunction:
    def __init__(self, pyctypefn, fn: callable, arglen: int, name: str):
        self._inner = pyctypefn(fn)
        self._fn = fn
        self._name = name
        inner_address = ctypes.cast(self._inner, ctypes.c_void_p)

        cmds = [
            b"\x48\x83\xec\x38",  # sub rsp, 0x38
            b"\x57",  # push rdi
            b"\x56",  # push rsi
            b"\x48\x89\xCF",  # mov rdi, rcx
            b"\x48\x89\xD6",  # mov rsi, rdx
            b"\x4C\x89\xC2",  # mov rdx, r8
            b"\x4C\x89\xC9",  # mov rcx, r9
            b"\x48\xB8", inner_address.value.to_bytes(8, "little"),  # movabs rax, 0x0
            b"\xFF\xD0",  # call rax
            b"\x5E",  # pop rsi
            b"\x5F",  # pop rdi
            b"\x48\x83\xc4\x38",  # add rsp, 0x38
            b"\xC3",  # ret
        ]

        cmds = bytearray().join(cmds)
        self._address = allocate_executable_memory(len(cmds))
        ctypes.memmove(self._address.value,
                       ctypes.addressof((ctypes.c_uint8 * len(cmds)).from_buffer(cmds)),
                       len(cmds))

    def address(self):
        return self._address

    def __call__(self, *args):
        return self._fn(*args)


class StdCallFunc32ByFunctionPointer:
    def __init__(self, ptr: int, argtypes, noargtypefn, name: str):
        self._name = name
        self._ptr = ptr
        self._argtypes = argtypes
        self._codelen = 1 + sum((ctypes.sizeof(argtype) + 3) // 4 * 5 for argtype in argtypes) + 8
        self._noargtypefn = noargtypefn
        self._codeptr = allocate_executable_memory(self._codelen)

    def address(self):
        return ctypes.c_void_p(self._ptr)

    def __call__(self, *args):
        buf = (ctypes.c_uint8 * self._codelen).from_address(self._codeptr.value)
        buf[0] = 0x90
        i = 1
        for argtype, arg in zip(reversed(self._argtypes), reversed(args)):
            arglen = ctypes.sizeof(argtype)
            if not isinstance(arg, argtype):
                arg = argtype(arg)
            argb = (ctypes.c_uint8 * arglen).from_address(ctypes.addressof(arg))
            j = 0
            while j < arglen - 3:
                buf[i] = 0x68
                buf[i + 1] = argb[0]
                buf[i + 2] = argb[1]
                buf[i + 3] = argb[2]
                buf[i + 4] = argb[3]
                i += 5
                j += 4
            if j != arglen:
                buf[i] = 0x68
                buf[i + 1] = argb[0]
                buf[i + 2] = argb[1] if j + 1 <= arglen else 0
                buf[i + 3] = argb[2] if j + 2 <= arglen else 0
                buf[i + 4] = argb[3] if j + 3 <= arglen else 0
                i += 5
        buf[i] = 0xb8
        ctypes.c_uint32.from_address(self._codeptr.value + i + 1).value = self._ptr
        buf[i + 5] = 0xff
        buf[i + 6] = 0xd0
        buf[i + 7] = 0xc3

        res = self._noargtypefn(self._codeptr.value)()

        return res


class StdCallFunc64ByFunctionPointer:
    def __init__(self, ptr: int, argtypes, noargtypefn, name: str):
        self._ptr = ptr
        self._argtypes = argtypes
        self._noargtypefn = noargtypefn
        self._name = name

        movabs_regs = (
            b"\x48\xb9",  # movabs rcx, imm
            b"\x48\xba",  # movabs rdx, imm
            b"\x49\xb8",  # movabs r8, imm
            b"\x49\xb9",  # movabs r9, imm
        )

        cmds = [
            b"\x57",  # push rdi
            b"\x56",  # push rsi

            # sub rsp, imm
            b"\x48\x83\xec",
            (0x8 + (len(argtypes) + 1) // 2 * 2 * 8).to_bytes(1, "little"),
        ]
        self._offsets = []

        for i, argtype in enumerate(self._argtypes):
            if i < len(movabs_regs):
                cmds.append(movabs_regs[i])
                self._offsets.append(sum(len(x) for x in cmds))
                cmds.append(bytes(8))
            else:
                # movabs rax, imm
                cmds.append(b"\x48\xb8")
                self._offsets.append(sum(len(x) for x in cmds))
                cmds.append(bytes(8))

                # mov qword ptr [rsp + N], rax
                cmds.append(b"\x48\x89\x44\x24")
                cmds.append((i * 8).to_bytes(1, "little"))

        # movabs rax, imm
        cmds.append(b"\x48\xb8")
        cmds.append(self._ptr.to_bytes(8, "little"))

        cmds.append(b"\xff\xd0")  # call rax

        # add rsp, imm
        cmds.append(b"\x48\x83\xc4" + (0x8 + (len(argtypes) + 1) // 2 * 2 * 8).to_bytes(1, "little"))

        cmds.append(b"\x5e")  # pop rsi
        cmds.append(b"\x5f")  # pop rdi
        cmds.append(b"\xc3")  # ret

        self._template = bytearray().join(cmds)
        self._codeptr = allocate_executable_memory(len(self._template))
        ctypes.memmove(self._codeptr.value,
                       ctypes.addressof(ctypes.c_uint8.from_buffer(self._template)),
                       len(self._template))

    def address(self):
        return ctypes.c_void_p(self._ptr)

    def __call__(self, *args):
        for argtype, arg, offset in zip(self._argtypes, args, self._offsets):
            arglen = ctypes.sizeof(argtype)
            if not isinstance(arg, argtype):
                arg = argtype(arg)
            ctypes.memmove(self._codeptr.value + offset, ctypes.addressof(arg), arglen)

        res = self._noargtypefn(self._codeptr.value)()
        return res


class StdCallFunc32Type:
    def __init__(self, restype, *argtypes, name: typing.Optional[str] = None):
        self._name = name or ("(" + ", ".join(str(x) for x in (restype, *argtypes)) + ")")
        self._restype = restype
        self._argtypes = argtypes
        self._arglen = sum((ctypes.sizeof(argtype) + 3) // 4 * 4 for argtype in self._argtypes)
        self._noarg_type = ctypes.CFUNCTYPE(restype)
        self._pytype = ctypes.CFUNCTYPE(restype, *argtypes)

    def __call__(self, ptr):
        if callable(ptr):
            return StdCallFunc32ByPythonFunction(self._pytype, ptr, self._arglen, self._name)
        elif isinstance(ptr, int):
            return StdCallFunc32ByFunctionPointer(ptr, self._argtypes, self._noarg_type, self._name)
        else:
            raise TypeError


class StdCallFunc64Type:
    def __init__(self, restype, *argtypes, name: typing.Optional[str] = None):
        self._name = name or ("(" + ", ".join(str(x) for x in (restype, *argtypes)) + ")")
        self._restype = restype
        self._argtypes = argtypes
        self._arglen = sum((ctypes.sizeof(argtype) + 3) // 4 * 4 for argtype in self._argtypes)
        self._noarg_type = ctypes.CFUNCTYPE(restype)
        self._pytype = ctypes.CFUNCTYPE(restype, *argtypes)

    def __call__(self, ptr):
        if callable(ptr):
            return StdCallFunc64ByPythonFunction(self._pytype, ptr, self._arglen, self._name)
        elif isinstance(ptr, int):
            return StdCallFunc64ByFunctionPointer(ptr, self._argtypes, self._noarg_type, self._name)
        else:
            raise TypeError


if POINTER_SIZE == 4:
    StdCallFuncType = StdCallFunc32Type
else:
    StdCallFuncType = StdCallFunc64Type

# endregion

# region Oodle typedefs

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


# endregion

# region ZiPatch typedefs


class ZiPatchHeader(ctypes.BigEndianStructure):
    SIGNATURE = b"\x91\x5A\x49\x50\x41\x54\x43\x48\x0d\x0a\x1a\x0a"

    _fields_ = (
        ("signature", ctypes.c_char * 12),
    )

    signature: typing.Union[int, ctypes.c_char * 12]


class ZiPatchChunkHeader(ctypes.BigEndianStructure):
    _fields_ = (
        ("size", ctypes.c_uint32),
        ("type", ctypes.c_char * 4),
    )

    size: typing.Union[int, ctypes.c_uint32]
    type: typing.Union[bytes, ctypes.c_char * 4]


class ZiPatchChunkFooter(ctypes.BigEndianStructure):
    _fields_ = (
        ("crc32", ctypes.c_uint32),
    )

    crc32: typing.Union[int, ctypes.c_uint32]


class ZiPatchSqpackHeader(ctypes.BigEndianStructure):
    _fields_ = (
        ("size", ctypes.c_uint32),
        ("command", ctypes.c_char * 4),
    )

    size: typing.Union[int, ctypes.c_uint32]
    command: typing.Union[bytes, ctypes.c_char * 4]


class ZiPatchSqpackFileAddHeader(ctypes.BigEndianStructure):
    COMMAND = b'FA'

    _fields_ = (
        ("offset", ctypes.c_uint64),
        ("size", ctypes.c_uint64),
        ("path_size", ctypes.c_uint32),
        ("expac_id", ctypes.c_uint16),
        ("padding1", ctypes.c_uint16),
    )

    offset: typing.Union[int, ctypes.c_uint16]
    size: typing.Union[int, ctypes.c_uint64]
    path_size: typing.Union[int, ctypes.c_uint32]
    expac_id: typing.Union[int, ctypes.c_uint16]
    padding1: typing.Union[int, ctypes.c_uint16]


class ZiPatchSqpackFileDeleteHeader(ctypes.BigEndianStructure):
    COMMAND = b'FD'

    _fields_ = (
        ("offset", ctypes.c_uint64),
        ("size", ctypes.c_uint64),
        ("path_size", ctypes.c_uint32),
        ("expac_id", ctypes.c_uint16),
        ("padding1", ctypes.c_uint16),
    )

    offset: typing.Union[int, ctypes.c_uint16]
    size: typing.Union[int, ctypes.c_uint64]
    path_size: typing.Union[int, ctypes.c_uint32]
    expac_id: typing.Union[int, ctypes.c_uint16]
    padding1: typing.Union[int, ctypes.c_uint16]


class ZiPatchSqpackFileResolver(ctypes.BigEndianStructure):
    _fields_ = (
        ("main_id", ctypes.c_uint16),
        ("sub_id", ctypes.c_uint16),
        ("file_id", ctypes.c_uint32),
    )

    main_id: typing.Union[int, ctypes.c_uint16]
    sub_id: typing.Union[int, ctypes.c_uint16]
    file_id: typing.Union[int, ctypes.c_uint32]

    @property
    def expac_id(self):
        return self.sub_id >> 8

    @property
    def path(self):
        if self.expac_id == 0:
            return f"sqpack/ffxiv/{self.main_id:02x}{self.sub_id:04x}.win32"
        else:
            return f"sqpack/ex{self.expac_id}/{self.main_id:02x}{self.sub_id:04x}.win32"


class ZiPatchSqpackAddData(ZiPatchSqpackFileResolver):
    COMMAND = b'A'

    _fields_ = (
        ("block_offset_value", ctypes.c_uint32),
        ("block_size_value", ctypes.c_uint32),
        ("clear_size_value", ctypes.c_uint32),
    )

    @property
    def block_offset(self):
        return self.block_offset_value * 128

    @property
    def block_size(self):
        return self.block_size_value * 128

    @property
    def clear_size(self):
        return self.clear_size_value * 128

    @property
    def path(self):
        return super().path + f".dat{self.file_id}"


class ZiPatchSqpackZeroData(ZiPatchSqpackFileResolver):
    COMMANDS = {b'E', b'D'}

    _fields_ = (
        ("block_offset_value", ctypes.c_uint32),
        ("block_size_value", ctypes.c_uint32),
    )

    @property
    def block_offset(self):
        return self.block_offset_value * 128

    @property
    def block_size(self):
        return self.block_size_value * 128

    @property
    def path(self):
        return super().path + f".dat{self.file_id}"


class BlockHeader(ctypes.LittleEndianStructure):
    COMPRESSED_SIZE_NOT_COMPRESSED = 32000

    _fields_ = (
        ("header_length", ctypes.c_uint32),
        ("version", ctypes.c_uint32),
        ("compressed_size", ctypes.c_uint32),
        ("decompressed_size", ctypes.c_uint32),
    )

    header_length: int
    version: int
    compressed_size: int
    decompressed_size: int

    data: typing.Optional[bytes] = None

    def is_compressed(self):
        return self.compressed_size != BlockHeader.COMPRESSED_SIZE_NOT_COMPRESSED and self.decompressed_size != 1


# endregion

# region Game network typedefs

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
    def find(cls, data: typing.Union[bytearray, memoryview], oodle: 'BaseOodleHelper', oodle_channel: int):
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

            try:
                bundle_header = cls.from_buffer(data, offset)
                if len(data) - offset < bundle_header.length:
                    raise ValueError
                bundle_data = data[offset + ctypes.sizeof(bundle_header):offset + bundle_header.length]
                bundle_length = bundle_header.length  # copy it, as it may get changed later
            except ValueError:
                break  # incomplete data

            try:
                if bundle_header.compression == 0:
                    pass
                elif bundle_header.compression == 1:
                    bundle_data = bytearray(zlib.decompress(bundle_data))
                elif bundle_header.compression == 2:
                    bundle_data = bytearray(oodle.decode(oodle_channel, bundle_data, bundle_header.decoded_body_length))
                else:
                    raise RuntimeError(f"Unsupported compression method {bundle_header.compression}")

                bundle_data_offset = 0
                messages = list()
                for i in range(bundle_header.message_count):
                    message_header = XivMessageHeader.from_buffer(bundle_data, bundle_data_offset)
                    if message_header.length < ctypes.sizeof(message_header):
                        raise InvalidDataException
                    message_data = bundle_data[bundle_data_offset + ctypes.sizeof(message_header):
                                               bundle_data_offset + message_header.length]
                    messages.append((message_header, message_data))
                    bundle_data_offset += message_header.length
                    if bundle_data_offset > len(bundle_data):
                        raise InvalidDataException

                offset += bundle_length
                yield bundle_header, messages

            except Exception as e:
                if not isinstance(e, InvalidDataException):
                    logging.exception("Unknown error occurred while trying to parse bundle")
                yield data[offset:offset + 1]
                offset += 1
        return offset


# endregion

# region Opcode definition and misc game version specific configuration

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
    Common_UseOodleTcp: bool
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


def load_definitions(update_opcodes: bool):
    if os.path.exists("definitions.json"):
        try:
            if update_opcodes:
                raise RuntimeError("Force update requested")
            if os.path.getmtime("definitions.json") + 60 * 60 < time.time():
                raise RuntimeError("Definitions file older than an hour")
            with open("definitions.json", "r") as fp:
                return [OpcodeDefinition.from_dict(x) for x in json.load(fp)]
        except Exception as e:
            logging.info(f"Failed to read previous opcode definition files: {e}")

    definitions_raw = []
    logging.info("Downloading opcode definition files...")
    try:
        with urllib.request.urlopen(OPCODE_DEFINITION_LIST_URL) as resp:
            filelist = json.load(resp)

        for f in filelist:
            if f["name"][-5:].lower() != '.json':
                continue
            with urllib.request.urlopen(f["download_url"]) as resp:
                data = json.load(resp)
            data["Name"] = f["name"]
            definitions_raw.append(data)
    except Exception as e:
        raise RuntimeError(f"Failed to load opcode definition") from e
    with open("definitions.json", "w") as fp:
        json.dump(definitions_raw, fp)
    definitions = [OpcodeDefinition.from_dict(x) for x in definitions_raw]
    return definitions


def load_rules(port: int, definitions: typing.List[OpcodeDefinition], nftables: bool) -> typing.Set[str]:
    rules = set()
    for definition in definitions:
        for iprange in definition.Server_IpRange:
            if nftables:
                if isinstance(iprange, ipaddress.IPv4Network):
                    rule = f"ip daddr {iprange}"
                else:
                    rule = f"ip daddr {iprange[0]}-{iprange[1]}"
                for port1, port2 in definition.Server_PortRange:
                    rules.add(f"{rule} tcp dport {port1}-{port2}")
            else:
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
                rules.add(" ".join(rule))
    return rules


# endregion

# region Implementation


@dataclasses.dataclass
class SocketSet:
    oodle_tcp_base_channel: int
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
                 definitions: typing.List[OpcodeDefinition], args: ArgumentTuple,
                 firehose_write_fd: int):
        self.args = args
        self.firehose_write_fd = firehose_write_fd

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
            self.oodle = OodleHelper()
            self._use_oodle_tcp = definition.Common_UseOodleTcp

            break
        else:
            self.opcodes = None
            self.oodle = None
            dn = "-"
        logging.info(f"New[{dn}] {self.downstream.getsockname()} {self.downstream.getpeername()} {self.destination}")

    def to_upstream(self, bundle_header: XivBundleHeader,
                    messages: typing.List[typing.Tuple[XivMessageHeader, bytearray]]):
        for message_header, message_data in messages:
            if message_header.type != XivMessageType.Ipc:
                continue
            try:
                ipc = XivMessageIpcHeader.from_buffer(message_data)
                if ipc.type != XivMessageIpcType.UnknownButInterested:
                    continue
                if self.opcodes.is_request(ipc.subtype):
                    request = XivMessageIpcActionRequest.from_buffer(message_data, ctypes.sizeof(ipc))
                    self.pending_actions.append(PendingAction(request.action_id, request.sequence))

                    # If somehow latest action request has been made before last animation lock end time, keep it.
                    # Otherwise...
                    if self.pending_actions[-1].request_timestamp > self.last_animation_lock_ends_at:

                        # If there was no action queued to begin with before the current one,
                        # update the base lock time to now.
                        if len(self.pending_actions) == 1:
                            self.last_animation_lock_ends_at = self.pending_actions[-1].request_timestamp

                    logging.info(f"C2S_ActionRequest: actionId={request.action_id:04x} sequence={request.sequence:04x}")
            except Exception as e:
                logging.exception(f"unknown error {e} occurred in upstream handler; skipping")
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
                if (ipc.type == XivMessageIpcType.XivMitmLatencyMitigatorCustom
                        and ipc.subtype == XivMitmLatencyMitigatorCustomSubtype.OriginalWaitTime):
                    data = XivMessageIpcCustomOriginalWaitTime.from_buffer(message_data, ctypes.sizeof(ipc))
                    wait_time_dict[data.source_sequence] = data.original_wait_time
                if ipc.type != XivMessageIpcType.UnknownButInterested:
                    continue
                if self.opcodes.is_action_effect(ipc.subtype):
                    effect = XivMessageIpcActionEffect.from_buffer(message_data, ctypes.sizeof(ipc))
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
                    control = XivMessageIpcActorControlSelf.from_buffer(message_data, ctypes.sizeof(ipc))
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
                    control = XivMessageIpcActorControl.from_buffer(message_data, ctypes.sizeof(ipc))
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
                    cast = XivMessageIpcActorCast.from_buffer(message_data, ctypes.sizeof(ipc))

                    # Mark that the last request was a cast.
                    # If it indeed is a cast, the game UI will block the user from generating additional requests,
                    # so first item is guaranteed to be the cast action.
                    if self.pending_actions:
                        self.pending_actions[0].is_cast = True

                    logging.info(f"S2C_ActorCast: actionId={cast.action_id:04x} type={cast.skill_type:04x} "
                                 f"action_id_2={cast.action_id_2:04x} time={cast.cast_time:.3f} "
                                 f"target_id={cast.target_id:08x}")

            except Exception as e:
                logging.exception(f"unknown error {e} occurred in downstream handler; skipping")
        for i, message_header, message_data in reversed(message_insertions):
            messages.insert(i, (message_header, message_data))
        return bundle_header, messages

    def run(self):
        bundle_header: XivBundleHeader
        messages: typing.List[typing.Tuple[XivMessageHeader, bytearray]]

        self.upstream.settimeout(3)
        with contextlib.ExitStack() as estack:
            estack.enter_context(self.downstream)
            estack.enter_context(self.upstream)
            if self.oodle is not None:
                estack.enter_context(self.oodle)

            try:
                self.upstream.connect((str(self.destination[0]), self.destination[1]))
                self.upstream.settimeout(None)

                check_targets = (
                    (self.downstream, SocketSet(0, self.downstream, self.upstream, "D->U", self.to_upstream)),
                    (self.upstream, SocketSet(2, self.upstream, self.downstream, "U->D", self.to_downstream)),
                )
                while True:
                    rlist = [
                        k for k, v in check_targets if v.incoming is not None
                    ]
                    wlist = [
                        k for k, v in check_targets if v.outgoing
                    ]
                    if not rlist and not wlist:
                        break

                    rlist, wlist, _ = select.select(rlist, wlist, [], 60)
                    if not rlist and not wlist:  # timeout or empty
                        break

                    for direction, (_, target) in enumerate(check_targets):
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
                                it = XivBundleHeader.find(
                                    bytearray(target.incoming), self.oodle,
                                    target.oodle_tcp_base_channel if self._use_oodle_tcp else 0xFFFFFFFF)
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

                                        bundle_header.decoded_body_length = len(message_bytes)
                                        bundle_header.message_count = len(messages)

                                        if self.firehose_write_fd != -1:
                                            original_compression = bundle_header.compression
                                            bundle_header.compression = 0
                                            bundle_header.length = ctypes.sizeof(bundle_header) + len(message_bytes)
                                            os.write(self.firehose_write_fd,
                                                     (8 + bundle_header.length).to_bytes(4, "little"))
                                            os.write(self.firehose_write_fd, direction.to_bytes(8, "little"))

                                            # noinspection PyTypeChecker
                                            os.write(self.firehose_write_fd, bytes(bundle_header))
                                            os.write(self.firehose_write_fd, message_bytes)
                                            bundle_header.compression = original_compression

                                        if bundle_header.compression == 1:
                                            message_bytes = zlib.compress(message_bytes)
                                        elif bundle_header.compression == 2:
                                            message_bytes = self.oodle.encode(
                                                target.oodle_tcp_base_channel + 1 if self._use_oodle_tcp else 0xFFFFFFFF,
                                                message_bytes)

                                        bundle_header.length = ctypes.sizeof(bundle_header) + len(message_bytes)

                                        # noinspection PyTypeChecker
                                        target.outgoing.extend(bytes(bundle_header))
                                        target.outgoing.extend(message_bytes)

                    for direction, target in check_targets:
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


# endregion

# region ZiPatch download/unpacker

def download_exe(src_url: str):
    print("Downloading:", src_url)
    with urllib.request.urlopen(src_url) as resp:
        data = bytearray(resp.read())
    if data[0:2] == b'MZ':
        dosh = ImageDosHeader.from_buffer(data)
        nth = ImageNtHeaders32.from_buffer(dosh.e_lfanew)
        if nth.FileHeader.Machine == 0x014c:
            print("x86 binary detected; treating the file as ffxiv.exe")
            with open("ffxiv.exe", "wb") as fp:
                fp.write(data)
        elif nth.FileHeader.Machine == 0x8664:
            print("x86 binary detected; treating the file as ffxiv_dx11.exe")
            with open("ffxiv_dx11.exe", "wb") as fp:
                fp.write(data)
        return

    print("Looking for ffxiv.exe and ffxiv_dx11.exe in the downloaded patch file...")
    with io.BytesIO(data) as fp:
        fp.seek(0, os.SEEK_SET)
        fp: typing.Union[typing.BinaryIO, io.BytesIO]
        fp.readinto(hdr := ZiPatchHeader())
        if hdr.signature != ZiPatchHeader.SIGNATURE:
            raise RuntimeError("downloaded file is neither a .patch file or .exe file")

        target_files = {
            "ffxiv.exe": [],
            "ffxiv_dx11.exe": [],
        }

        while fp.readinto(hdr := ZiPatchChunkHeader()):
            offset = fp.tell()
            if hdr.type == b"SQPK":
                fp.readinto(sqpkhdr := ZiPatchSqpackHeader())
                if sqpkhdr.command in (b"T", b"X"):
                    pass

                elif sqpkhdr.command == ZiPatchSqpackFileAddHeader.COMMAND:
                    fp.readinto(sqpkhdr2 := ZiPatchSqpackFileAddHeader())
                    path = fp.read(sqpkhdr2.path_size).split(b"\0", 1)[0].decode("utf-8")
                    target_file = target_files.get(path, None)
                    chunks = []

                    current_file_offset = sqpkhdr2.offset
                    if target_file is not None:
                        if current_file_offset == 0:
                            target_file.clear()
                        target_file.append((current_file_offset, chunks))
                    while fp.tell() < offset + hdr.size:
                        fp.readinto(block_header := BlockHeader())
                        block_data_size = block_header.compressed_size if block_header.is_compressed() else block_header.decompressed_size
                        padded_block_size = (block_data_size + ctypes.sizeof(block_header) + 127) & 0xFFFFFF80
                        if target_file is not None:
                            x = fp.read(padded_block_size - ctypes.sizeof(block_header))[:block_data_size]
                            if block_header.is_compressed():
                                x = zlib.decompress(x, -zlib.MAX_WBITS)
                            if len(x) != block_header.decompressed_size:
                                raise RuntimeError("Corrupt patch file")
                            chunks.append(x)
                        else:
                            fp.seek(padded_block_size - ctypes.sizeof(block_header), os.SEEK_CUR)
                        current_file_offset += block_header.decompressed_size

                elif sqpkhdr.command == ZiPatchSqpackFileDeleteHeader.COMMAND:
                    fp.readinto(sqpkhdr2 := ZiPatchSqpackFileDeleteHeader())
                    fp.seek(sqpkhdr2.path_size, io.SEEK_CUR)

                elif sqpkhdr.command == ZiPatchSqpackAddData.COMMAND:
                    fp.readinto(sqpkhdr2 := ZiPatchSqpackAddData())

                elif sqpkhdr.command in ZiPatchSqpackZeroData.COMMANDS:
                    fp.readinto(sqpkhdr2 := ZiPatchSqpackZeroData())

                elif sqpkhdr.command in {b'HDV', b'HDI', b'HDD', b'HIV', b'HII', b'HID'}:
                    fp.readinto(sqpkhdr2 := ZiPatchSqpackFileResolver())

            fp.seek(offset + hdr.size, os.SEEK_SET)
            fp.readinto(ZiPatchChunkFooter())
            if hdr.type == b"EOF_":
                break

    found_any_file = False
    for target_file_name, target_file_data in target_files.items():
        if not target_file_data:
            continue
        with open(target_file_name, "wb") as fp:
            for offset, chunks in target_file_data:
                fp.seek(offset, os.SEEK_SET)
                fp.writelines(chunks)
        print(f"Saved: {target_file_name}")
        found_any_file = True

    if not found_any_file:
        raise RuntimeError("downloaded patch file does not contain a .exe file")


# endregion

# region Oodle

# region Oodle wrappers

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


# endregion


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
            2: OodleInstance(self._module, True),
            3: OodleInstance(self._module, True),
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
    def init_module(cls):
        if POINTER_SIZE == 4:
            if not os.path.exists("ffxiv.exe"):
                raise RuntimeError("Need ffxiv.exe in the same directory. "
                                   "Copy one from your local Windows/Mac installation.")

            cls._module = OodleModule(PeImage(pathlib.Path("ffxiv.exe").read_bytes()))
        elif POINTER_SIZE == 8:
            if not os.path.exists("ffxiv_dx11.exe"):
                raise RuntimeError("Need ffxiv_dx11.exe in the same directory. "
                                   "Copy one from your local Windows/Mac installation.")

            cls._module = OodleModule(PeImage(pathlib.Path("ffxiv_dx11.exe").read_bytes()))


OodleHelper = OodleWithBudgetAbiThunks


def test_oodle():
    testval = b'\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x04' * 16
    with OodleHelper() as oodle:
        enc = oodle.encode(0, testval)
        dec = oodle.decode(1, enc, len(testval))
        if testval != dec:
            print(testval)
            print(enc)
            print(dec)
            print(f"Oodle test fail (TCP)")
            return False
        enc = oodle.encode(0xFFFFFFFF, testval)
        dec = oodle.decode(0xFFFFFFFF, enc, len(testval))
        if testval != dec:
            print(testval)
            print(enc)
            print(dec)
            print(f"Oodle test fail (UDP)")
            return False
    return True


# endregion


def __main__() -> int:
    if sys.version_info < (3, 8):
        print("This script requires at least python 3.8")
        return -1

    logging.basicConfig(level=logging.INFO, force=True,
                        format="%(asctime)s\t%(process)d(main)\t%(levelname)s\t%(message)s",
                        handlers=[
                            logging.StreamHandler(sys.stderr),
                        ])

    parser = argparse.ArgumentParser("XivMitmLatencyMitigator: https://github.com/Soreepeong/XivMitmLatencyMitigator")
    parser.add_argument("-r", "--region", action="append", dest="region", default=[], choices=("JP", "CN", "KR"),
                        help="Filters connection by regions. Can be specified multiple times.")
    parser.add_argument("-e", "--extra-delay", action="store", dest="extra_delay", default=0.075, type=float,
                        help=EXTRA_DELAY_HELP)
    parser.add_argument("-m", "--measure-ping", action="store_true", dest="measure_ping", default=False,
                        help="Use measured latency information from sockets to server and client to adjust extra delay."
                        )
    parser.add_argument("-u", "--update-opcodes", action="store_true", dest="update_opcodes", default=False,
                        help="Download new opcodes again; do not use cached opcodes file.")
    parser.add_argument("-x", "--exe", action="append", dest="exe_url", default=[],
                        help="Download ffxiv.exe and/or ffxiv_dx11.exe from specified URL (exe or patch file.)")
    parser.add_argument("-n", "--nftables", action="store_true", dest="nftables", default=False,
                        help="Use nft instead of iptables.")
    parser.add_argument("--firehose", action="store", dest="firehose", default=None,
                        help="Open a TCP listening socket that will receive all decoded game networking data transferred. (ex: 0.0.0.0:1234)")

    args: typing.Union[ArgumentTuple, argparse.Namespace] = parser.parse_args()

    if args.extra_delay < 0:
        logging.warning("Extra delay cannot be a negative number.")
        return -1

    for url in args.exe_url:
        url = url.strip()
        if url:
            download_exe(url)

    logging.info(f"Region filter: {', '.join(args.region) if args.region else '(None)'}")
    logging.info(f"Extra delay: {args.extra_delay}s")
    logging.info(f"Use measured socket latency: {'yes' if args.measure_ping else 'no'}")

    if sys.platform == 'linux':
        OodleWithBudgetAbiThunks.init_module()
    else:
        logging.warning("Only linux is supported at the moment.")
        return -1

    if not test_oodle():
        print("Oodle test fail")
        return -1

    poller = select.poll()

    if args.firehose:
        firehose_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        poller.register(firehose_listener.fileno(), select.POLLIN)
        ip, port = args.firehose.split(":")
        port = int(port)
        firehose_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        firehose_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        firehose_listener.bind((ip, port))
        firehose_listener.listen(32)
        logging.info(f"Firehose listening on {firehose_listener.getsockname()}...")
    else:
        firehose_listener = None

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    poller.register(listener.fileno(), select.POLLIN)
    if hasattr(socket, "TCP_NODELAY"):
        listener.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
    if hasattr(socket, "TCP_QUICKACK"):
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

    removal_cmds = []
    err = 0
    is_child = False
    cleanup_filename = os.path.basename(__file__) + ".cleanup.sh"
    if os.path.exists(cleanup_filename):
        os.system(cleanup_filename)

    child_pid_to_rfd: typing.Dict[int, int] = {}
    child_rfds: typing.Set[int] = set()
    firehose_clients: typing.Dict[int, socket.socket] = {}
    firehose_backlog: typing.Dict[int, typing.Deque[typing.Tuple[int, bytearray]]] = {}

    try:
        with open(cleanup_filename, "w") as fp:
            fp.write("#!/bin/sh\n")
            for i, rule in enumerate(load_rules(port, definitions, args.nftables)):
                if args.nftables:
                    add_cmd = f"nft rule ip nat PREROUTING {rule} dnat 127.0.0.1:{port} comment XMLM_{os.getpid()}_{i}_"
                else:
                    add_cmd = f"iptables -t nat -I PREROUTING {rule} -j REDIRECT --to {port}"
                logging.info(f"Running: {add_cmd}")
                if os.system(add_cmd):
                    raise RootRequiredError

                if args.nftables:
                    h = os.popen(f"nft --handle list ruleset | grep XMLM_{os.getpid()}_{i}_").read().strip().split(" ")[-1]
                    remove_cmd = f"nft delete rule ip nat PREROUTING handle {h}"
                else:
                    remove_cmd = f"iptables -t nat -D PREROUTING {rule} -j REDIRECT --to {port}"
                removal_cmds.append(remove_cmd)
                fp.write(f"{remove_cmd}\n")

            if args.nftables:
                if os.system(f"nft rule ip filter INPUT tcp dport {port} accept comment XMLM_{os.getpid()}_P"):
                    raise RootRequiredError
                h = os.popen(f"nft --handle list ruleset | grep XMLM_{os.getpid()}_P").read().strip().split(" ")[-1]
                remove_cmd = f"nft delete rule ip nat PREROUTING handle {h}"
                removal_cmds.append(remove_cmd)
                fp.write(f"{remove_cmd}\n")
        os.chmod(cleanup_filename, 0o777)

        removal_cmds.append("sysctl -w " + os.popen("sysctl net.ipv4.ip_forward")
                            .read().strip().replace(" ", ""))
        os.system("sysctl -w net.ipv4.ip_forward=1")

        removal_cmds.append("sysctl -w " + os.popen("sysctl net.ipv4.conf.all.route_localnet")
                            .read().strip().replace(" ", ""))
        os.system("sysctl -w net.ipv4.conf.all.route_localnet=1")

        listener.listen(32)
        logging.info(f"Listening on {listener.getsockname()}...")
        logging.info("Press Ctrl+C to quit.")

        def on_child_exit(signum, frame):
            if child_pid_to_rfd:
                pid, status = os.waitpid(-1, os.WNOHANG)
                if pid:
                    logging.info(f"[{pid:<6}] has exit with status code {status}.")
                    fd = child_pid_to_rfd.pop(pid, None)
                    if fd is not None:
                        try:
                            poller.unregister(fd)
                        except KeyError:
                            pass

        signal.signal(signal.SIGCHLD, on_child_exit)

        while True:
            for child_pid in child_pid_to_rfd:
                try:
                    os.kill(child_pid, 0)
                except OSError:
                    rfd = child_pid_to_rfd.pop(child_pid, None)
                    if rfd is not None:
                        child_rfds.discard(rfd)
                        try:
                            poller.unregister(rfd)
                        except KeyError:
                            pass
                        os.close(rfd)

            for fd, event_type in poller.poll():
                # print(fd, event_type)
                if fd == listener.fileno():
                    if event_type & select.POLLIN:
                        sock, source = listener.accept()

                        if firehose_listener is None:
                            rfd = wfd = -1
                        else:
                            rfd, wfd = os.pipe()

                        child_pid = os.fork()
                        if child_pid == 0:
                            is_child = True
                            child_pid_to_rfd.clear()
                            listener.close()
                            if firehose_listener is not None:
                                os.close(rfd)
                                firehose_listener.close()
                                for c in firehose_clients.values():
                                    c.close()
                                firehose_clients.clear()
                                firehose_backlog.clear()

                            return Connection(sock, source, definitions, args, wfd).run()

                        sock.close()
                        if wfd != -1:
                            os.close(wfd)
                        if rfd != -1:
                            poller.register(rfd, select.POLLIN)
                            child_pid_to_rfd[child_pid] = rfd
                            child_rfds.add(rfd)

                elif fd in child_rfds:
                    if event_type & select.POLLIN:
                        try:
                            data = [os.read(fd, 4)]
                            cb = int.from_bytes(data[0], "little")

                            offset = 0
                            while offset < cb:
                                data.append(os.read(fd, cb - offset))
                                offset += len(data[-1])
                                if not len(data[-1]):
                                    print("Child read fail")
                                    break
                            else:
                                data = bytearray().join(data)
                                # print(f"Child read: {cb} bytes =>{len(data)}")
                                for clientfd, backlog in firehose_backlog.items():
                                    poller.modify(clientfd, select.POLLIN | select.POLLOUT | select.POLLRDHUP)
                                    backlog.append((0, data))
                        except OSError:
                            pass

                    elif event_type & select.POLLHUP:
                        try:
                            poller.unregister(fd)
                        except KeyError:
                            pass

                elif firehose_listener is not None and fd == firehose_listener.fileno():
                    if event_type & select.POLLIN:
                        try:
                            sock, source = firehose_listener.accept()
                            firehose_clients[sock.fileno()] = sock
                            firehose_backlog[sock.fileno()] = collections.deque()
                            poller.register(sock.fileno(), select.POLLRDHUP | select.POLLIN)
                            sock.setblocking(False)
                        except OSError:
                            pass

                elif fd in firehose_clients:
                    abandon_sock = bool(event_type & (select.POLLRDHUP | select.POLLHUP))
                    try:
                        sock = firehose_clients[fd]

                        if event_type & select.POLLIN:
                            while True:
                                try:
                                    recv_data = sock.recv(4096)
                                except socket.error as e:
                                    if e.errno in (errno.EWOULDBLOCK, errno.EAGAIN):
                                        break
                                    raise
                                if not recv_data:
                                    break
                                firehose_backlog[fd].append((0, bytearray().join((
                                    int.to_bytes(len(recv_data) + 8, 4, "little"),
                                    b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF',
                                    recv_data,
                                ))))
                                poller.modify(fd, select.POLLIN | select.POLLOUT | select.POLLRDHUP)

                        if event_type & select.POLLOUT:
                            sock = firehose_clients[fd]
                            while firehose_backlog[fd]:
                                offset, data = firehose_backlog[fd][0]
                                while offset < len(data):
                                    try:
                                        sent = sock.send(data)
                                        if not sent:
                                            break
                                        offset += sent
                                    except socket.error as e:
                                        if e.errno in (errno.EWOULDBLOCK, errno.EAGAIN):
                                            break
                                        raise
                                if offset == len(data):
                                    firehose_backlog[fd].popleft()
                                else:
                                    firehose_backlog[fd][0] = offset, data
                            else:
                                poller.modify(fd, select.POLLRDHUP | select.POLLIN)
                    except socket.error as e:
                        print(e)
                        abandon_sock = True

                    if abandon_sock:
                        poller.unregister(fd)
                        firehose_backlog.pop(fd)
                        firehose_clients.pop(fd).close()

    except RootRequiredError:
        logging.error("This program requires root permissions.\n")
        err = -1

    except KeyboardInterrupt:
        pass

    finally:
        for child_pid in child_pid_to_rfd.keys():
            try:
                os.kill(child_pid, signal.SIGINT)
            except OSError:
                pass

        if not is_child:
            logging.info("Cleaning up...")
            for removal_cmd in removal_cmds:
                logging.info(f"Running: {removal_cmd}")
                exit_code = os.system(removal_cmd)
                if exit_code:
                    logging.warning(f"\t=> Failed with exit code {exit_code}")
                    err = -1
            os.remove(cleanup_filename)
            if err:
                logging.error("One or more error have occurred during cleanup.")
                err = -1
            else:
                logging.info("Cleanup complete.")
    return err


if __name__ == "__main__":
    exit(__main__())
