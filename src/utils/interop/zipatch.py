import ctypes
import io
import os
import typing
import urllib.request
import zlib

from utils.interop.win32 import ImageDosHeader, ImageNtHeaders32


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


def download_exe(src_url: str):
    print("Downloading:", src_url)
    with (open(src_url, "rb") if os.path.exists(src_url) else urllib.request.urlopen(src_url)) as resp:
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

                else:
                    print(f"Skipping {hdr.type}:{sqpkhdr.command}")

            fp.seek(offset + hdr.size, os.SEEK_SET)
            fp.readinto(ZiPatchChunkFooter())
            if hdr.type == b"EOF_":
                break
            elif hdr.type != b"SQPK":
                print(f"Skipping {hdr.type}")

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
