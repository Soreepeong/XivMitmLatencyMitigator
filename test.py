import ctypes
import ctypes.util
import os
import pathlib
import re
import sys
import typing

import mmap

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
    e_magic: int | ctypes.c_uint16
    e_cblp: int | ctypes.c_uint16
    e_cp: int | ctypes.c_uint16
    e_crlc: int | ctypes.c_uint16
    e_cparhdr: int | ctypes.c_uint16
    e_minalloc: int | ctypes.c_uint16
    e_maxalloc: int | ctypes.c_uint16
    e_ss: int | ctypes.c_uint16
    e_sp: int | ctypes.c_uint16
    e_csum: int | ctypes.c_uint16
    e_ip: int | ctypes.c_uint16
    e_cs: int | ctypes.c_uint16
    e_lfarlc: int | ctypes.c_uint16
    e_ovno: int | ctypes.c_uint16
    e_res: typing.Sequence[int] | ctypes.c_uint16 * 4
    e_oemid: int | ctypes.c_uint16
    e_oeminfo: int | ctypes.c_uint16
    e_res2: typing.Sequence[int] | ctypes.c_uint16 * 10
    e_lfanew: int | ctypes.c_uint32


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
    Machine: int | ctypes.c_uint16
    NumberOfSections: int | ctypes.c_uint16
    TimeDateStamp: int | ctypes.c_uint32
    PointerToSymbolTable: int | ctypes.c_uint32
    NumberOfSymbols: int | ctypes.c_uint32
    SizeOfOptionalHeader: int | ctypes.c_uint16
    Characteristics: int | ctypes.c_uint16


class ImageDataDirectory(ctypes.LittleEndianStructure):
    _fields_ = (
        ("VirtualAddress", ctypes.c_uint32),
        ("Size", ctypes.c_uint32),
    )
    VirtualAddress: int | ctypes.c_uint32
    Size: int | ctypes.c_uint32


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
    Magic: int | ctypes.c_uint16
    MajorLinkerVersion: int | ctypes.c_uint8
    MinorLinkerVersion: int | ctypes.c_uint8
    SizeOfCode: int | ctypes.c_uint32
    SizeOfInitializedData: int | ctypes.c_uint32
    SizeOfUninitializedData: int | ctypes.c_uint32
    AddressOfEntryPoint: int | ctypes.c_uint32
    BaseOfCode: int | ctypes.c_uint32
    BaseOfData: int | ctypes.c_uint32
    ImageBase: int | ctypes.c_uint32
    SectionAlignment: int | ctypes.c_uint32
    FileAlignment: int | ctypes.c_uint32
    MajorOperatingSystemVersion: int | ctypes.c_uint16
    MinorOperatingSystemVersion: int | ctypes.c_uint16
    MajorImageVersion: int | ctypes.c_uint16
    MinorImageVersion: int | ctypes.c_uint16
    MajorSubsystemVersion: int | ctypes.c_uint16
    MinorSubsystemVersion: int | ctypes.c_uint16
    Win32VersionValue: int | ctypes.c_uint32
    SizeOfImage: int | ctypes.c_uint32
    SizeOfHeaders: int | ctypes.c_uint32
    CheckSum: int | ctypes.c_uint32
    Subsystem: int | ctypes.c_uint16
    DllCharacteristics: int | ctypes.c_uint16
    SizeOfStackReserve: int | ctypes.c_uint32
    SizeOfStackCommit: int | ctypes.c_uint32
    SizeOfHeapReserve: int | ctypes.c_uint32
    SizeOfHeapCommit: int | ctypes.c_uint32
    LoaderFlags: int | ctypes.c_uint32
    NumberOfRvaAndSizes: int | ctypes.c_uint32
    DataDirectory: typing.Sequence[ImageDataDirectory] | ImageDataDirectory * IMAGE_NUMBEROF_DIRECTORY_ENTRIES


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
    Magic: int | ctypes.c_uint16
    MajorLinkerVersion: int | ctypes.c_uint8
    MinorLinkerVersion: int | ctypes.c_uint8
    SizeOfCode: int | ctypes.c_uint32
    SizeOfInitializedData: int | ctypes.c_uint32
    SizeOfUninitializedData: int | ctypes.c_uint32
    AddressOfEntryPoint: int | ctypes.c_uint32
    BaseOfCode: int | ctypes.c_uint32
    ImageBase: int | ctypes.c_uint64
    SectionAlignment: int | ctypes.c_uint32
    FileAlignment: int | ctypes.c_uint32
    MajorOperatingSystemVersion: int | ctypes.c_uint16
    MinorOperatingSystemVersion: int | ctypes.c_uint16
    MajorImageVersion: int | ctypes.c_uint16
    MinorImageVersion: int | ctypes.c_uint16
    MajorSubsystemVersion: int | ctypes.c_uint16
    MinorSubsystemVersion: int | ctypes.c_uint16
    Win32VersionValue: int | ctypes.c_uint32
    SizeOfImage: int | ctypes.c_uint32
    SizeOfHeaders: int | ctypes.c_uint32
    CheckSum: int | ctypes.c_uint32
    Subsystem: int | ctypes.c_uint16
    DllCharacteristics: int | ctypes.c_uint16
    SizeOfStackReserve: int | ctypes.c_uint64
    SizeOfStackCommit: int | ctypes.c_uint64
    SizeOfHeapReserve: int | ctypes.c_uint64
    SizeOfHeapCommit: int | ctypes.c_uint64
    LoaderFlags: int | ctypes.c_uint32
    NumberOfRvaAndSizes: int | ctypes.c_uint32
    DataDirectory: typing.Sequence[ImageDataDirectory] | ImageDataDirectory * IMAGE_NUMBEROF_DIRECTORY_ENTRIES


class ImageNtHeaders32(ctypes.LittleEndianStructure):
    _fields_ = (
        ("Signature", ctypes.c_uint32),
        ("FileHeader", ImageFileHeader),
        ("OptionalHeader", ImageOptionalHeader32),
    )
    Signature: int | ctypes.c_uint32
    FileHeader: ImageFileHeader
    OptionalHeader: ImageOptionalHeader32


class ImageNtHeaders64(ctypes.LittleEndianStructure):
    _fields_ = (
        ("Signature", ctypes.c_uint32),
        ("FileHeader", ImageFileHeader),
        ("OptionalHeader", ImageOptionalHeader64),
    )
    Signature: int | ctypes.c_uint32
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
    Name: bytes | ctypes.c_char * IMAGE_SIZEOF_SHORT_NAME
    VirtualSize: int | ctypes.c_uint32
    VirtualAddress: int | ctypes.c_uint32
    SizeOfRawData: int | ctypes.c_uint32
    PointerToRawData: int | ctypes.c_uint32
    PointerToRelocations: int | ctypes.c_uint32
    PointerToLinenumbers: int | ctypes.c_uint32
    NumberOfRelocations: int | ctypes.c_uint16
    NumberOfLinenumbers: int | ctypes.c_uint16
    Characteristics: int | ctypes.c_uint32


class ImageBaseRelocation(ctypes.LittleEndianStructure):
    _fields_ = (
        ("VirtualAddress", ctypes.c_uint32),
        ("SizeOfBlock", ctypes.c_uint32),
    )
    VirtualAddress: int | ctypes.c_uint32
    SizeOfBlock: int | ctypes.c_uint32


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
    def __init__(self, data: bytearray | bytes):
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

        self.sections: typing.Sequence[ImageSectionHeader] | ctypes.Array[ImageSectionHeader] = (
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

    def section(self, section: bytes | ImageSectionHeader) -> memoryview:
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

    def address(self):
        return ctypes.c_void_p(self._ptr)

    def __call__(self, *args):
        codeptr = allocate_executable_memory(self._codelen)
        buf = (ctypes.c_uint8 * self._codelen).from_address(codeptr.value)
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
        ctypes.c_uint32.from_address(codeptr.value + i + 1).value = self._ptr
        buf[i + 5] = 0xff
        buf[i + 6] = 0xd0
        buf[i + 7] = 0xc3

        res = self._noargtypefn(codeptr.value)()
        free_executable_memory(codeptr)

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

    def address(self):
        return ctypes.c_void_p(self._ptr)

    def __call__(self, *args):
        codeptr = allocate_executable_memory(len(self._template))
        ctypes.memmove(codeptr.value,
                       ctypes.addressof(ctypes.c_uint8.from_buffer(self._template)),
                       len(self._template))

        cmd = self._template
        for argtype, arg, offset in zip(self._argtypes, args, self._offsets):
            arglen = ctypes.sizeof(argtype)
            if not isinstance(arg, argtype):
                arg = argtype(arg)
            ctypes.memmove(codeptr.value + offset, ctypes.addressof(arg), arglen)

        res = self._noargtypefn(codeptr.value)()
        free_executable_memory(codeptr)
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
            pattern = br"\x75\x04\x48\x89\x7e.\xe8(....)\x4c..\xe8(....).{0,256}\x01\x75\x0a\x48\x8b\x0f\xe8(....)\xeb\x09\x48\x8b\x4f\x08\xe8(....)"
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
            match = text_view.index(pattern)
            if match == -1:
                raise RuntimeError("_alloca_probe not found")
            image.view[text.VirtualAddress + match] = 0xc3

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

    def encode(self, src: bytes | bytearray | memoryview) -> bytearray:
        if not isinstance(src, (bytearray, memoryview)):
            src = bytearray(src)
        enc = bytearray(len(src) + 8)
        del enc[self._encode_function(
            ctypes.addressof(self._state),
            ctypes.addressof(self._shared),
            ctypes.addressof(ctypes.c_byte.from_buffer(src)), len(src),
            ctypes.addressof(ctypes.c_byte.from_buffer(enc))):]
        return enc

    def decode(self, enc: bytes | bytearray | memoryview, result_length: int) -> bytearray:
        dec = bytearray(result_length)
        if not self._decode_function(
                ctypes.addressof(self._state),
                ctypes.addressof(self._shared),
                ctypes.addressof(ctypes.c_byte.from_buffer(enc)), len(enc),
                ctypes.addressof(ctypes.c_byte.from_buffer(dec)), len(dec)):
            raise RuntimeError("Oodle decode fail")
        return dec


# endregion

def __main__():
    if POINTER_SIZE not in (4, 8):
        raise NotImplementedError

    img = PeImage(pathlib.Path("ffxiv_dx11.exe" if POINTER_SIZE == 8 else "ffxiv.exe").read_bytes())
    oodle_module = OodleModule(img)

    test_data = b'000003211561116515468046454464656456456456' * 16

    oodle_udp = OodleInstance(oodle_module, False)
    if test_data != oodle_udp.decode(oodle_udp.encode(test_data), len(test_data)):
        print("Fail UDP")

    oodle_tcp1 = OodleInstance(oodle_module, True)
    oodle_tcp2 = OodleInstance(oodle_module, True)
    if test_data != oodle_tcp2.decode(xd := oodle_tcp1.encode(test_data), len(test_data)):
        print("Fail TCP")

    print("OK")


if __name__ == "__main__":
    exit(__main__())
