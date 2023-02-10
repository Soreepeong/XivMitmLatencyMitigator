import ctypes.util
import os
import pathlib
import re
import sys
import typing

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


def allocate_executable_memory(length: int):
    if os.name == "nt":
        virtualalloc = ctypes.windll.kernel32.VirtualAlloc
        virtualalloc.argtypes = (ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_uint32)
        virtualalloc.restype = ctypes.c_void_p
        return ctypes.c_void_p(virtualalloc(0,
                                            length,
                                            0x3000,  # MEM_RESERVE | MEM_COMMIT
                                            0x40))  # PAGE_EXECUTE_READWRITE
    else:
        raise NotImplementedError


POINTER_SIZE = ctypes.sizeof(ctypes.c_void_p)
if os.name == 'nt':
    crt_malloc = ctypes.cdll.msvcrt.malloc
    crt_free = ctypes.cdll.msvcrt.free
else:
    libc = ctypes.CDLL(ctypes.util.find_library("c"))
    crt_malloc = libc.malloc
    crt_free = libc.free
crt_malloc.argtypes = (ctypes.c_size_t,)
crt_malloc.restype = ctypes.c_size_t
crt_free.argtypes = (ctypes.c_size_t,)

PyMemoryView_FromMemory = ctypes.pythonapi.PyMemoryView_FromMemory
PyMemoryView_FromMemory.argtypes = (ctypes.c_void_p, ctypes.c_ssize_t, ctypes.c_int)
PyMemoryView_FromMemory.restype = ctypes.py_object


def my_malloc(size: int, align: int) -> int:
    raw = crt_malloc(size + align + POINTER_SIZE - 1)
    if raw == 0:
        return 0

    aligned = (raw + align + 7) & ((~align & (sys.maxsize * 2 + 1)) + 1)
    original = aligned - POINTER_SIZE
    ctypes.memmove(ctypes.c_void_p(original), ctypes.addressof(ctypes.c_void_p(raw)), 8)
    return aligned


def my_free(aligned: int):
    original = ctypes.cast(ctypes.c_void_p(aligned - POINTER_SIZE),
                           ctypes.POINTER(ctypes.c_size_t))
    raw = original.contents
    crt_free(raw)


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
        copy_length = self.dos.e_lfanew + ctypes.sizeof(self.nt) + ctypes.sizeof(self.sections)

        ctypes.memmove(self.address, (ctypes.c_byte * len(self._data)).from_buffer(self._data), copy_length)
        for shdr in self.sections:
            section_len = min(shdr.SizeOfRawData, shdr.VirtualSize)
            ctypes.memmove(ctypes.c_void_p(self.address.value + shdr.VirtualAddress),
                           (ctypes.c_byte * section_len).from_buffer(self._data, shdr.PointerToRawData),
                           section_len)

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


class Oodle:
    try:
        _FT = ctypes.WINFUNCTYPE
    except AttributeError:
        raise NotImplementedError
    _OodleNetwork1_Shared_Size = _FT(ctypes.c_int32, ctypes.c_int32)
    _OodleNetwork1_Shared_SetWindow = _FT(None, ctypes.c_void_p, ctypes.c_int32, ctypes.c_void_p, ctypes.c_int32)
    _OodleNetwork1UDP_Train = _FT(None, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_int32), ctypes.c_int32)
    _OodleNetwork1UDP_Decode = _FT(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t)
    _OodleNetwork1UDP_Encode = _FT(ctypes.c_int32, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p)
    _OodleNetwork1UDP_State_Size = _FT(ctypes.c_int32)
    _Oodle_Malloc = _FT(ctypes.c_size_t, ctypes.c_size_t, ctypes.c_int32)
    _Oodle_Free = _FT(None, ctypes.c_size_t)
    _Oodle_SetMallocFree = _FT(None, _Oodle_Malloc, _Oodle_Free)

    def __init__(self, image: PeImage, htbits: int, window: int = 0x100000):
        self._image = image

        text = image.section_header(b".text")
        text_view = image.section(text)
        if POINTER_SIZE == 8:
            first = re.search(rb"\x48\x83\x7b.\x00\x75.\xb9.\x00\x00\x00\xe8....\x45\x33\xc0\x33\xd2\x48\x8b\xc8\xe8",
                              text_view, re.DOTALL).start(0) + text.VirtualAddress
        else:
            first = re.search(rb"\x83\x7e..\x75.\x6a.\xe8....\x6a\x00\x6a\x00\x50\xe8",
                              text_view, re.DOTALL).start(0) + text.VirtualAddress
        calls = []
        for i in range(first, len(text_view) - 4):
            if image.view[i] != 0xE8:
                continue
            target_address = image.resolve_rip_relative(i)
            if 0 <= target_address < len(text_view):
                calls.append(target_address)
                if len(calls) == 5:
                    break
        else:
            raise RuntimeError("Fail")

        self._oodlenetwork1_shared_size = self._OodleNetwork1_Shared_Size(calls[0] + image.address.value)
        self._oodlenetwork1_shared_setwindow = self._OodleNetwork1_Shared_SetWindow(calls[2] + image.address.value)
        self._oodlenetwork1udp_state_size = self._OodleNetwork1UDP_State_Size(
            re.search(rb"\xcc\xb8\x00\xb4\x2e\x00",
                      text_view, re.DOTALL).start(0) + text.VirtualAddress + image.address.value + 1)

        if POINTER_SIZE == 8:
            self._oodle_set_malloc_free = self._Oodle_SetMallocFree(image.resolve_rip_relative(
                re.search(rb"\x80\x3d\xaa....\x75.\x48\x8d\x15....\x48\x8d\x0d....\xe8",  # TODO
                          text_view, re.DOTALL).start(0) + text.VirtualAddress + 23) + image.address.value)
            self._oodlenetwork1udp_train = self._OodleNetwork1UDP_Train(
                re.search(
                    rb"\x48\x89\x5c\x24\x08\x48\x89\x6c\x24\x10\x48\x89\x74\x24\x18\x48\x89\x7c\x24\x20\x41\x56\x48\x83\xec\x30\x48\x8b\xf2",
                    text_view, re.DOTALL).start(0) + text.VirtualAddress + image.address.value)
            self._oodlenetwork1udp_decode = self._OodleNetwork1UDP_Decode(
                re.search(rb"\x40\x53\x48\x83\xec.\x48\x8b\x44\x24\x68\x49\x8b\xd9\x48\x85\xc0\x7e",
                          text_view, re.DOTALL).start(0) + text.VirtualAddress + image.address.value)
            self._oodlenetwork1udp_encode = self._OodleNetwork1UDP_Encode(
                re.search(
                    rb"\x4c\x89\x4c\x24\x20\x4c\x89\x44\x24\x18\x48\x89\x4c\x24\x08\x55\x56\x57\x41\x55\x41\x57\x48\x8d\x6c\x24\xd1",
                    text_view, re.DOTALL).start(0) + text.VirtualAddress + image.address.value)
        else:
            self._oodle_set_malloc_free = self._Oodle_SetMallocFree(xd := image.resolve_rip_relative(
                re.search(rb"\x75\x16\x68....\x68....\xe8",
                          text_view, re.DOTALL).start(0) + text.VirtualAddress + 12) + image.address.value)
            self._oodlenetwork1udp_train = self._OodleNetwork1UDP_Train(
                re.search(rb"\x56\x6a\x08\x68\x00\x84\x4a\x00",
                          text_view, re.DOTALL).start(0) + text.VirtualAddress + image.address.value)
            self._oodlenetwork1udp_decode = self._OodleNetwork1UDP_Decode(
                re.search(rb"\x8b\x44\x24\x18\x56\x85\xc0\x7e.\x8b\x74\x24\x14\x85\xf6\x7e.\x3b\xf0",
                          text_view, re.DOTALL).start(0) + text.VirtualAddress + image.address.value)
            self._oodlenetwork1udp_encode = self._OodleNetwork1UDP_Encode(
                re.search(
                    rb"\xff\x74\x24\x14\x8b\x4c\x24\x08\xff\x74\x24\x14\xff\x74\x24\x14\xff\x74\x24\x14\xe8....\xc2\x14\x00\xcc\xcc\xcc\xcc\xb8",
                    text_view, re.DOTALL).start(0) + text.VirtualAddress + image.address.value)

        c_my_malloc = self._Oodle_Malloc(my_malloc)
        c_my_free = self._Oodle_Free(my_free)

        self._oodle_set_malloc_free(c_my_malloc, c_my_free)
        self._state = (ctypes.c_uint8 * self._oodlenetwork1udp_state_size())()
        self._shared = (ctypes.c_uint8 * self._oodlenetwork1_shared_size(htbits))()
        self._window = (ctypes.c_uint8 * window)()
        self._oodlenetwork1_shared_setwindow(self._shared, htbits, self._window, len(self._window))
        self._oodlenetwork1udp_train(self._state, self._shared, None, None, 0)

    def encode(self, src: bytes | bytearray | memoryview) -> bytearray:
        if not isinstance(src, (bytearray, memoryview)):
            src = bytearray(src)
        enc = bytearray(len(src))
        del enc[self._oodlenetwork1udp_encode(self._state, self._shared,
                                              (ctypes.c_byte * len(src)).from_buffer(src), len(src),
                                              (ctypes.c_byte * len(enc)).from_buffer(enc)):]
        return enc

    def decode(self, enc: bytes | bytearray | memoryview, result_length: int) -> bytearray:
        dec = bytearray(result_length)
        if not self._oodlenetwork1udp_decode(self._state, self._shared,
                                             (ctypes.c_byte * len(enc)).from_buffer(enc), len(enc),
                                             (ctypes.c_byte * len(dec)).from_buffer(dec), len(dec)):
            raise RuntimeError("Oodle decode fail")
        return dec

    def selftest(self):
        src = bytearray(i // 8 for i in range(256))
        enc = self.encode(src)
        dec = self.decode(enc, len(src))
        if src != dec:
            raise RuntimeError("Self-test failed")


def __main__():
    if POINTER_SIZE not in (4, 8):
        raise NotImplementedError

    my_free(my_malloc(63, 8))
    oodle = Oodle(PeImage(pathlib.Path("ffxiv_dx11.exe" if POINTER_SIZE == 8 else "ffxiv.exe").read_bytes()))
    oodle.selftest()


if __name__ == "__main__":
    exit(__main__())
