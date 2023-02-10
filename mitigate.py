#!/usr/bin/sudo python
import argparse
import collections
import ctypes
import dataclasses
import datetime
import enum
import io
import ipaddress
import json
import logging.handlers
import math
import os
import platform
import random
import shlex
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
import typing
import urllib.request
import zlib

import select

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

OODLE_HELPER_CODE = r"""
#define _CRT_SECURE_NO_WARNINGS

#include <fstream>
#include <iostream>
#include <span>
#include <type_traits>
#include <vector>

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16
#define IMAGE_DIRECTORY_ENTRY_BASERELOC 5
#define IMAGE_SIZEOF_SHORT_NAME 8

struct IMAGE_DOS_HEADER {
	uint16_t e_magic;
	uint16_t e_cblp;
	uint16_t e_cp;
	uint16_t e_crlc;
	uint16_t e_cparhdr;
	uint16_t e_minalloc;
	uint16_t e_maxalloc;
	uint16_t e_ss;
	uint16_t e_sp;
	uint16_t e_csum;
	uint16_t e_ip;
	uint16_t e_cs;
	uint16_t e_lfarlc;
	uint16_t e_ovno;
	uint16_t e_res[4];
	uint16_t e_oemid;
	uint16_t e_oeminfo;
	uint16_t e_res2[10];
	uint32_t e_lfanew;
};

struct IMAGE_FILE_HEADER {
	uint16_t Machine;
	uint16_t NumberOfSections;
	uint32_t TimeDateStamp;
	uint32_t PointerToSymbolTable;
	uint32_t NumberOfSymbols;
	uint16_t SizeOfOptionalHeader;
	uint16_t Characteristics;
};

struct IMAGE_DATA_DIRECTORY {
	uint32_t VirtualAddress;
	uint32_t Size;
};

struct IMAGE_OPTIONAL_HEADER32 {
	uint16_t Magic;
	uint8_t MajorLinkerVersion;
	uint8_t MinorLinkerVersion;
	uint32_t SizeOfCode;
	uint32_t SizeOfInitializedData;
	uint32_t SizeOfUninitializedData;
	uint32_t AddressOfEntryPoint;
	uint32_t BaseOfCode;
	uint32_t BaseOfData;
	uint32_t ImageBase;
	uint32_t SectionAlignment;
	uint32_t FileAlignment;
	uint16_t MajorOperatingSystemVersion;
	uint16_t MinorOperatingSystemVersion;
	uint16_t MajorImageVersion;
	uint16_t MinorImageVersion;
	uint16_t MajorSubsystemVersion;
	uint16_t MinorSubsystemVersion;
	uint32_t Win32VersionValue;
	uint32_t SizeOfImage;
	uint32_t SizeOfHeaders;
	uint32_t CheckSum;
	uint16_t Subsystem;
	uint16_t DllCharacteristics;
	uint32_t SizeOfStackReserve;
	uint32_t SizeOfStackCommit;
	uint32_t SizeOfHeapReserve;
	uint32_t SizeOfHeapCommit;
	uint32_t LoaderFlags;
	uint32_t NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
};

struct IMAGE_OPTIONAL_HEADER64 {
	uint16_t Magic;
	uint8_t MajorLinkerVersion;
	uint8_t MinorLinkerVersion;
	uint32_t SizeOfCode;
	uint32_t SizeOfInitializedData;
	uint32_t SizeOfUninitializedData;
	uint32_t AddressOfEntryPoint;
	uint32_t BaseOfCode;
	uint64_t ImageBase;
	uint32_t SectionAlignment;
	uint32_t FileAlignment;
	uint16_t MajorOperatingSystemVersion;
	uint16_t MinorOperatingSystemVersion;
	uint16_t MajorImageVersion;
	uint16_t MinorImageVersion;
	uint16_t MajorSubsystemVersion;
	uint16_t MinorSubsystemVersion;
	uint32_t Win32VersionValue;
	uint32_t SizeOfImage;
	uint32_t SizeOfHeaders;
	uint32_t CheckSum;
	uint16_t Subsystem;
	uint16_t DllCharacteristics;
	uint64_t SizeOfStackReserve;
	uint64_t SizeOfStackCommit;
	uint64_t SizeOfHeapReserve;
	uint64_t SizeOfHeapCommit;
	uint32_t LoaderFlags;
	uint32_t NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
};

template<typename TOptionalHeader>
struct IMAGE_NT_HEADERS_SIZED {
	uint32_t Signature;
	IMAGE_FILE_HEADER FileHeader;
	TOptionalHeader OptionalHeader;
};

struct IMAGE_SECTION_HEADER {
	char Name[IMAGE_SIZEOF_SHORT_NAME];
	union {
		uint32_t PhysicalAddress;
		uint32_t VirtualSize;
	} Misc;
	uint32_t VirtualAddress;
	uint32_t SizeOfRawData;
	uint32_t PointerToRawData;
	uint32_t PointerToRelocations;
	uint32_t PointerToLinenumbers;
	uint16_t NumberOfRelocations;
	uint16_t NumberOfLinenumbers;
	uint32_t Characteristics;
};

struct IMAGE_BASE_RELOCATION {
	uint32_t VirtualAddress;
	uint32_t SizeOfBlock;
};

#define FIELD_OFFSET(type, field)    ((int32_t)(int64_t)&(((type *)0)->field))
#define IMAGE_FIRST_SECTION( ntheader ) ((IMAGE_SECTION_HEADER*)        \
    ((const char*)(ntheader) +                                            \
     FIELD_OFFSET( IMAGE_NT_HEADERS, OptionalHeader ) +                 \
     ((ntheader))->FileHeader.SizeOfOptionalHeader   \
    ))

#if defined(_WIN64)
#define STDCALL __stdcall
const auto GamePath = LR"(C:\Program Files (x86)\SquareEnix\FINAL FANTASY XIV - A Realm Reborn\game\ffxiv_dx11.exe)";

extern "C" void* __stdcall VirtualAlloc(void* lpAddress, size_t dwSize, uint32_t flAllocationType, uint32_t flProtect);
void* executable_allocate(size_t size) {
	return VirtualAlloc(nullptr, size, 0x3000 /* MEM_COMMIT | MEM_RESERVE */, 0x40 /* PAGE_EXECUTE_READWRITE */);
}

using IMAGE_NT_HEADERS = IMAGE_NT_HEADERS_SIZED<IMAGE_OPTIONAL_HEADER64>;

#elif defined(_WIN32)
#define STDCALL __stdcall
const auto GamePath = LR"(C:\Program Files (x86)\SquareEnix\FINAL FANTASY XIV - A Realm Reborn\game\ffxiv.exe)";

extern "C" void* __stdcall VirtualAlloc(void* lpAddress, size_t dwSize, uint32_t flAllocationType, uint32_t flProtect);
void* executable_allocate(size_t size) {
	return VirtualAlloc(nullptr, size, 0x3000 /* MEM_COMMIT | MEM_RESERVE */, 0x40 /* PAGE_EXECUTE_READWRITE */);
}

using IMAGE_NT_HEADERS = IMAGE_NT_HEADERS_SIZED<IMAGE_OPTIONAL_HEADER32>;

#elif defined(__linux__)
#define STDCALL __attribute__((stdcall))
const auto GamePath = R"(ffxiv.exe)";

#include <stdlib.h>
#include <malloc.h>
#include <memory.h>
#include <unistd.h>
#include <sys/mman.h>
void* executable_allocate(size_t size) {
	const auto p = memalign(sysconf(_SC_PAGE_SIZE), size);
	mprotect(p, size, PROT_READ | PROT_WRITE | PROT_EXEC);
	return p;
}

using IMAGE_NT_HEADERS = IMAGE_NT_HEADERS_SIZED<IMAGE_OPTIONAL_HEADER32>;

#endif

using OodleNetwork1_Shared_Size = std::remove_pointer_t<int(STDCALL*)(int htbits)>;
using OodleNetwork1_Shared_SetWindow = std::remove_pointer_t<void(STDCALL*)(void* data, int htbits, void* window, int windowSize)>;
using OodleNetwork1UDP_Train = std::remove_pointer_t<void(STDCALL*)(void* state, void* shared, const void* const* trainingPacketPointers, const int* trainingPacketSizes, int trainingPacketCount)>;
using OodleNetwork1UDP_Decode = std::remove_pointer_t<bool(STDCALL*)(void* state, void* shared, const void* compressed, size_t compressedSize, void* raw, size_t rawSize)>;
using OodleNetwork1UDP_Encode = std::remove_pointer_t<int(STDCALL*)(const void* state, const void* shared, const void* raw, size_t rawSize, void* compressed)>;
using OodleNetwork1UDP_State_Size = std::remove_pointer_t<int(STDCALL*)(void)>;
using Oodle_Malloc = std::remove_pointer_t<void* (STDCALL*)(size_t size, int align)>;
using Oodle_Free = std::remove_pointer_t<void(STDCALL*)(void* p)>;
using Oodle_SetMallocFree = std::remove_pointer_t<void(STDCALL*)(Oodle_Malloc* pfnMalloc, Oodle_Free* pfnFree)>;

void* STDCALL my_malloc(size_t size, int align) {
	const auto pRaw = (char*)malloc(size + align + sizeof(void*) - 1);
	if (!pRaw)
		return nullptr;

	const auto pAligned = (void*)(((size_t)pRaw + align + 7) & (size_t)-align);
	*((void**)pAligned - 1) = pRaw;
	return pAligned;
}

void STDCALL my_free(void* p) {
	free(*((void**)p - 1));
}

const char* lookup_in_text(const char* pBaseAddress, const char* sPattern, const char* sMask, size_t length) {
	std::vector<void*> result;
	const std::string_view mask(sMask, length);
	const std::string_view pattern(sPattern, length);

	const auto& dosh = *(IMAGE_DOS_HEADER*)(&pBaseAddress[0]);
	const auto& nth = *(IMAGE_NT_HEADERS*)(&pBaseAddress[dosh.e_lfanew]);

	const auto pSectionHeaders = IMAGE_FIRST_SECTION(&nth);
	for (size_t i = 0; i < nth.FileHeader.NumberOfSections; ++i) {
		if (strncmp(pSectionHeaders[i].Name, ".text", 8) == 0) {
			std::string_view section(pBaseAddress + pSectionHeaders[i].VirtualAddress, pSectionHeaders[i].Misc.VirtualSize);
			const auto nUpperLimit = section.length() - pattern.length();
			for (size_t i = 0; i < nUpperLimit; ++i) {
				for (size_t j = 0; j < pattern.length(); ++j) {
					if ((section[i + j] & mask[j]) != (pattern[j] & mask[j]))
						goto next_char;
				}
				return section.data() + i;
			next_char:;
			}
		}
	}
	std::cerr << "Could not find signature" << std::endl;
	exit(-1);
	return nullptr;
}

int main() {
	std::cerr << std::hex;
	freopen(NULL, "rb", stdin);
	freopen(NULL, "wb", stdout);

	std::ifstream game(GamePath, std::ios::binary);
	game.seekg(0, std::ios::end);
	std::vector<char> buf((size_t)game.tellg());
	game.seekg(0, std::ios::beg);
	game.read(&buf[0], buf.size());

	const auto& dosh = *(IMAGE_DOS_HEADER*)(&buf[0]);
	const auto& nth = *(IMAGE_NT_HEADERS*)(&buf[dosh.e_lfanew]);

	std::span<char> virt((char*)executable_allocate(nth.OptionalHeader.SizeOfImage), nth.OptionalHeader.SizeOfImage);
	std::cerr << std::hex << "Base: 0x" << (size_t)&virt[0] << std::endl;

	const auto ddoff = dosh.e_lfanew + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER) + nth.FileHeader.SizeOfOptionalHeader;
	memcpy(&virt[0], &buf[0], ddoff + sizeof(IMAGE_SECTION_HEADER) * nth.FileHeader.NumberOfSections);
	for (const auto& s : std::span((IMAGE_SECTION_HEADER*)&buf[ddoff], nth.FileHeader.NumberOfSections)) {
		const auto src = std::span(&buf[s.PointerToRawData], s.SizeOfRawData);
		const auto dst = std::span(&virt[s.VirtualAddress], s.Misc.VirtualSize);
		memcpy(&dst[0], &src[0], std::min(src.size(), dst.size()));
	}

	const auto base = nth.OptionalHeader.ImageBase;
	for (size_t i = nth.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress,
		i_ = i + nth.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
		i < i_; ) {
		const auto& page = *(IMAGE_BASE_RELOCATION*)&virt[i];
		for (const auto relo : std::span((uint16_t*)(&page + 1), (page.SizeOfBlock - sizeof page) / 2)) {
			if ((relo >> 12) == 0)
				void();
			else if ((relo >> 12) == 3)
				*(uint32_t*)&virt[(size_t)page.VirtualAddress + (relo & 0xFFF)] += (uint32_t)((size_t)&virt[0] - base);
			else if ((relo >> 12) == 10)
				*(uint64_t*)&virt[(size_t)page.VirtualAddress + (relo & 0xFFF)] += (uint64_t)((size_t)&virt[0] - base);
			else
				std::abort();
		}

		i += page.SizeOfBlock;
	}

	const auto cpfnOodleSetMallocFree = lookup_in_text(
		&virt[0],
		"\x75\x16\x68\x00\x00\x00\x00\x68\x00\x00\x00\x00\xe8",
		"\xff\xff\xff\x00\x00\x00\x00\xff\x00\x00\x00\x00\xe8",
		13) + 12;
	const auto pfnOodleSetMallocFree = (Oodle_SetMallocFree*)(cpfnOodleSetMallocFree + 5 + *(int*)(cpfnOodleSetMallocFree + 1));

	std::vector<const char*> calls;
	for (auto sig1 = lookup_in_text(
		&virt[0],
		"\x83\x7e\x00\x00\x75\x00\x6a\x00\xe8\x00\x00\x00\x00\x6a\x00\x6a\x00\x50\xe8",
		"\xff\xff\x00\x00\xff\x00\xff\x00\xff\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff",
		19), sig2 = sig1 + 1024; calls.size() < 6 && sig1 < sig2; sig1++) {
		if (*sig1 != (char)0xe8)
			continue;
		const auto pTargetAddress = sig1 + 5 + *(int*)(sig1 + 1);
		if (pTargetAddress < virt.data() || pTargetAddress >= virt.data() + virt.size())
			continue;
		calls.push_back(pTargetAddress);
	}
	if (calls.size() < 5) {
		std::cerr << "Could not find signature" << std::endl;
		return -1;
	}
	const auto pfnOodleNetwork1_Shared_Size = (OodleNetwork1_Shared_Size*)calls[0];
	const auto pfnOodleNetwork1_Shared_SetWindow = (OodleNetwork1_Shared_SetWindow*)calls[2];
	const auto pfnOodleNetwork1UDP_State_Size = (OodleNetwork1UDP_State_Size*)(lookup_in_text(&virt[0],
		"\xcc\xb8\x00\xb4\x2e\x00",
		"\xff\xff\xff\xff\xff\xff",
		6) + 1
		);
	const auto pfnOodleNetwork1UDP_Train = (OodleNetwork1UDP_Train*)(lookup_in_text(&virt[0],
			"\x56\x6a\x08\x68\x00\x84\x4a\x00",
			"\xff\xff\xff\xff\xff\xff\xff\xff",
			8)
		);

	const auto pfnOodleNetwork1UDP_Decode = (OodleNetwork1UDP_Decode*)lookup_in_text(
		&virt[0],
		"\x8b\x44\x24\x18\x56\x85\xc0\x7e\x00\x8b\x74\x24\x14\x85\xf6\x7e\x00\x3b\xf0",
		"\xff\xff\xff\xff\xff\xff\xff\xff\x00\xff\xff\xff\xff\xff\xff\xff\x00\xff\xff",
		19);

	const auto pfnOodleNetwork1UDP_Encode = (OodleNetwork1UDP_Encode*)lookup_in_text(
		&virt[0],
		"\xff\x74\x24\x14\x8b\x4c\x24\x08\xff\x74\x24\x14\xff\x74\x24\x14\xff\x74\x24\x14\xe8\x00\x00\x00\x00\xc2\x14\x00\xcc\xcc\xcc\xcc\xb8",
		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff",
		33);

	int htbits = 19;
	pfnOodleSetMallocFree(&my_malloc, &my_free);
	std::vector<uint8_t> state(pfnOodleNetwork1UDP_State_Size());
	std::vector<uint8_t> shared(pfnOodleNetwork1_Shared_Size(htbits));
	std::vector<uint8_t> window(0x100000);

	pfnOodleNetwork1_Shared_SetWindow(&shared[0], htbits, &window[0], static_cast<int>(window.size()));
	pfnOodleNetwork1UDP_Train(&state[0], &shared[0], nullptr, nullptr, 0);

	std::vector<uint8_t> src, dst;
	src.resize(256);
	for (int i = 0; i < 256; i++)
		src[i] = i;
	dst.resize(src.size());
	dst.resize(pfnOodleNetwork1UDP_Encode(&state[0], &shared[0], &src[0], src.size(), &dst[0]));
	if (!pfnOodleNetwork1UDP_Decode(&state[0], &shared[0], &dst[0], dst.size(), &src[0], src.size())) {
		std::cerr << "Oodle encode/decode test failure" << std::endl;
		return -1;
	}
	else {
		std::cerr << "Oodle encode test: 256 -> " << dst.size() << std::endl;
	}
	for (int i = 0; i < 256; i++) {
		if (src[i] != i) {
			std::cerr << "Oodle encode/decode test failure" << std::endl;
			break;
		}
	}

	std::cerr << "Oodle helper running: state=" << state.size() << " shared=" << shared.size() << " window=" << window.size() << std::endl;
	while (true) {
		struct my_header_t {
			uint32_t SourceLength;
			uint32_t TargetLength;
		} hdr{};
		fread(&hdr, sizeof(hdr), 1, stdin);
		if (!hdr.SourceLength)
			return 0;

		// std::cerr << "Request: src=0x" << hdr.SourceLength << " dst=0x" << hdr.TargetLength << std::endl;
		src.resize(hdr.SourceLength);
		fread(&src[0], 1, src.size(), stdin);

		if (hdr.TargetLength == 0xFFFFFFFFU) {
			dst.resize(src.size());
			dst.resize(pfnOodleNetwork1UDP_Encode(&state[0], &shared[0], &src[0], src.size(), &dst[0]));
			// std::cerr << "Encoded: res=0x" << dst.size() << std::endl;
		}
		else {
			dst.resize(hdr.TargetLength);
			if (!pfnOodleNetwork1UDP_Decode(&state[0], &shared[0], &src[0], src.size(), &dst[0], dst.size())) {
				dst.resize(0);
				dst.resize(hdr.TargetLength);
			}
		}
		uint32_t size = (uint32_t)dst.size();
		fwrite(&size, sizeof(size), 1, stdout);
		fwrite(&dst[0], 1, dst.size(), stdout);
		fflush(stdout);
	}
}
"""


def clamp(v: T, min_: T, max_: T) -> T:
    return max(min_, min(max_, v))


class InvalidDataException(ValueError):
    pass


class RootRequiredError(RuntimeError):
    pass


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


class OodleHelper:
    oodle_helper_path: typing.Optional[str] = None
    _process: typing.ClassVar[typing.Optional[subprocess.Popen]] = None

    @classmethod
    def _init(cls):
        if cls._process is not None and cls._process.poll() is None:
            return

        cls._process = subprocess.Popen(cls.oodle_helper_path, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    @classmethod
    def decode(cls, data: bytes, declen: int) -> bytes:
        cls._init()

        cls._process: subprocess.Popen
        cls._process.stdin.write(int.to_bytes(len(data), 4, "little") + int.to_bytes(declen, 4, "little") + data)
        cls._process.stdin.flush()

        reslen = int.from_bytes(cls._process.stdout.read(4), "little")
        return cls._process.stdout.read(reslen)

    @classmethod
    def encode(cls, data: bytes) -> bytes:
        cls._init()

        cls._process: subprocess.Popen
        cls._process.stdin.write(int.to_bytes(len(data), 4, "little") + b'\xFF\xFF\xFF\xFF' + data)
        cls._process.stdin.flush()

        reslen = int.from_bytes(cls._process.stdout.read(4), "little")
        return cls._process.stdout.read(reslen)

    @classmethod
    def init_executable(cls):
        if not os.path.exists("ffxiv.exe"):
            raise RuntimeError("Need ffxiv.exe in the same directory. "
                               "Copy one from your local Windows/Mac installation.")

        cls.oodle_helper_path = os.path.dirname(__file__) + "/oodle_helper"
        with open(cls.oodle_helper_path + ".cpp", "w") as fp:
            fp.write(OODLE_HELPER_CODE)
        if platform.machine() not in ('i386', 'x86_64'):
            raise RuntimeError("Need to be able to run x86 binary natively")
        if os.system(f"g++ {shlex.quote(cls.oodle_helper_path)}.cpp -o {shlex.quote(cls.oodle_helper_path)}"
                     f" -std=c++20 -g -Og -m32"):
            os.unlink(cls.oodle_helper_path + ".cpp")
            raise RuntimeError("Failed to compile helper")
        os.unlink(cls.oodle_helper_path + ".cpp")


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
    def find(cls, data: typing.Union[bytearray, memoryview]):
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
                    bundle_data = bytearray(OodleHelper.decode(bundle_data, bundle_header.decoded_body_length))
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


@dataclasses.dataclass
class SocketSet:
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
                 definitions: typing.List[OpcodeDefinition], args: ArgumentTuple):
        self.args = args

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
            break
        else:
            self.opcodes = None
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
        with self.downstream, self.upstream:
            try:
                self.upstream.connect((str(self.destination[0]), self.destination[1]))
                self.upstream.settimeout(None)

                check_targets = {
                    self.downstream: SocketSet(self.downstream, self.upstream, "D->U", self.to_upstream),
                    self.upstream: SocketSet(self.upstream, self.downstream, "U->D", self.to_downstream),
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
                                logging.info(f"{target.log_prefix} Read finish")
                                target.incoming = None
                                continue

                            if self.opcodes is None:
                                target.outgoing.extend(data)
                            else:
                                target.incoming.extend(data)
                                it = XivBundleHeader.find(bytearray(target.incoming))
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
                                        if bundle_header.compression == 1:
                                            message_bytes = zlib.compress(message_bytes)
                                        elif bundle_header.compression == 2:
                                            message_bytes = OodleHelper.encode(message_bytes)

                                        bundle_header.message_count = len(messages)
                                        bundle_header.length = ctypes.sizeof(bundle_header) + len(message_bytes)

                                        # noinspection PyTypeChecker
                                        target.outgoing.extend(bytes(bundle_header))
                                        target.outgoing.extend(message_bytes)

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


def load_rules(port: int, definitions: typing.List[OpcodeDefinition]) -> typing.Set[str]:
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
    with urllib.request.urlopen(src_url) as resp:
        data = resp.read()
    if data[0:2] == b'MZ':
        with open("ffxiv.exe", "wb") as fp:
            fp.write(data)
        return

    print("Looking for ffxiv.exe in the downloaded patch file...")
    with io.BytesIO(data) as fp:
        fp.seek(0, os.SEEK_SET)
        fp: typing.Union[typing.BinaryIO, io.BytesIO]
        fp.readinto(hdr := ZiPatchHeader())
        if hdr.signature != ZiPatchHeader.SIGNATURE:
            raise RuntimeError("downloaded file is neither a .patch file or .exe file")

        ffxiv = []

        while fp.readinto(hdr := ZiPatchChunkHeader()):
            offset = fp.tell()
            if hdr.type == b"SQPK":
                fp.readinto(sqpkhdr := ZiPatchSqpackHeader())
                if sqpkhdr.command in (b"T", b"X"):
                    pass

                elif sqpkhdr.command == ZiPatchSqpackFileAddHeader.COMMAND:
                    fp.readinto(sqpkhdr2 := ZiPatchSqpackFileAddHeader())
                    path = fp.read(sqpkhdr2.path_size).split(b"\0", 1)[0].decode("utf-8")
                    is_target_file = path == 'ffxiv.exe'

                    current_file_offset = sqpkhdr2.offset
                    while fp.tell() < offset + hdr.size:
                        fp.readinto(block_header := BlockHeader())
                        block_data_size = block_header.compressed_size if block_header.is_compressed() else block_header.decompressed_size
                        padded_block_size = (block_data_size + ctypes.sizeof(block_header) + 127) & 0xFFFFFF80
                        if is_target_file:
                            x = fp.read(padded_block_size - ctypes.sizeof(block_header))[:block_data_size]
                            if block_header.is_compressed():
                                x = zlib.decompress(x, -zlib.MAX_WBITS)
                            if len(x) != block_header.decompressed_size:
                                raise RuntimeError("Corrupt patch file")
                            ffxiv.append(x)
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

    if ffxiv:
        with open("ffxiv.exe", "wb") as fp:
            fp.writelines(ffxiv)
        return

    raise RuntimeError("downloaded patch file does not contain a .exe file")


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
    parser.add_argument("-x", "--exe", action="store", type=str, dest="exe_url", default="",
                        help="Download ffxiv.exe from specified URL (exe or patch file.)")
    args: typing.Union[ArgumentTuple, argparse.Namespace] = parser.parse_args()

    if args.extra_delay < 0:
        logging.warning("Extra delay cannot be a negative number.")
        return -1

    if args.exe_url != '':
        download_exe(args.exe_url)

    logging.info(f"Region filter: {', '.join(args.region) if args.region else '(None)'}")
    logging.info(f"Extra delay: {args.extra_delay}s")
    logging.info(f"Use measured socket latency: {'yes' if args.measure_ping else 'no'}")

    OodleHelper.init_executable()
    testval = b'\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x04' * 16
    enc = OodleHelper.encode(testval)
    dec = OodleHelper.decode(enc, len(testval))
    if testval != dec:
        print("Oodle test fail")
        return -1

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
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

    applied_rules = []
    err = False
    is_child = False
    cleanup_filename = os.path.basename(__file__) + ".cleanup.sh"
    if os.path.exists(cleanup_filename):
        os.system(cleanup_filename)
    try:
        with open(cleanup_filename, "w") as fp:
            fp.write("#!/bin/sh\n")
            for rule in load_rules(port, definitions):
                iptables_cmd = f"iptables -t nat -I PREROUTING {rule}"
                logging.info(f"Running: {iptables_cmd}")
                if os.system(iptables_cmd):
                    raise RootRequiredError
                applied_rules.append(rule)
                fp.write(f"iptables -t nat -D PREROUTING {rule}\n")
        os.chmod(cleanup_filename, 0o777)

        os.system("sysctl -w net.ipv4.ip_forward=1")

        listener.listen(8)
        logging.info(f"Listening on {listener.getsockname()}...")
        logging.info("Press Ctrl+C to quit.")

        child_pids = set()

        def on_child_exit(signum, frame):
            if child_pids:
                pid, status = os.waitpid(-1, os.WNOHANG)
                if pid:
                    logging.info(f"[{pid:<6}] has exit with status code {status}.")
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
                is_child = True
                child_pids.clear()
                listener.close()
                return Connection(sock, source, definitions, args).run()
            sock.close()
            child_pids.add(child_pid)

        for child_pid in child_pids:
            try:
                os.kill(child_pid, signal.SIGINT)
            except OSError:
                pass

    except RootRequiredError:
        logging.error("This program requires root permissions.\n")
        err = True

    finally:
        if not is_child:
            logging.info("Cleaning up...")
            for rule in applied_rules:
                iptables_cmd = f"iptables -t nat -D PREROUTING {rule}"
                logging.info(f"Running: {iptables_cmd}")
                exit_code = os.system(iptables_cmd)
                if exit_code:
                    logging.warning(f"\t=> Failed with exit code {exit_code}")
                    err = True
            os.remove(cleanup_filename)
            if err:
                logging.error("One or more error have occurred during cleanup.")
                return -1
            else:
                logging.info("Cleanup complete.")
                return 0


if __name__ == "__main__":
    exit(__main__())
