import ctypes.util
import mmap
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
    DataDirectory: typing.Union[
        typing.Sequence[ImageDataDirectory],
        ImageDataDirectory * IMAGE_NUMBEROF_DIRECTORY_ENTRIES,
    ]


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
    DataDirectory: typing.Union[
        typing.Sequence[ImageDataDirectory],
        ImageDataDirectory * IMAGE_NUMBEROF_DIRECTORY_ENTRIES,
    ]


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
    def __init__(self, pyctypefn, fn: typing.Callable, arglen: int, name: str):
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
    def __init__(self, pyctypefn, fn: typing.Callable, arglen: int, name: str):
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
