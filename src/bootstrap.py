import contextlib
import grp
import io
import ipaddress
import logging
import os
import pathlib
import pwd
import signal
import socket
import stat
import subprocess
import time

from arguments import ArgumentTuple
from utils.consts import DUMMY_NET_NAME, CLEANUP_FILE_NAME
from utils.interop.linux import setup_dummy_adapter
from utils.interop.win32 import POINTER_SIZE
from utils.misc import getaddrinfo_for_tcp_with_port


def get_setuidgid(name: str) -> tuple[int | None, int | None]:
    if name == "":
        return None, None

    serve_as = name.split(":")
    if len(serve_as) == 1:
        t = pwd.getpwnam(serve_as[0])
        return t.pw_uid, t.pw_gid
    elif len(serve_as) == 2:
        return pwd.getpwnam(serve_as[0]).pw_uid, grp.getgrnam(serve_as[1]).gr_gid
    else:
        raise ValueError("must be in the format of username:groupname, if not username only")


def get_listen_sockaddrs(args: ArgumentTuple, getaddrinfo):
    sockaddrs = []
    for x in setup_dummy_adapter(
            DUMMY_NET_NAME, ipaddress.IPv4Address(args.dummy_addr4), ipaddress.IPv6Address(args.dummy_addr6)):
        if isinstance(x, ipaddress.IPv4Address):
            yield from getaddrinfo(str(x), 0, socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        elif isinstance(x, ipaddress.IPv6Address):
            yield from getaddrinfo(f"{x}%{DUMMY_NET_NAME}", 0, socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        else:
            raise AssertionError
    for x in args.listen:
        yield from getaddrinfo_for_tcp_with_port(x, getaddrinfo)
    return sockaddrs


def read_ffxiv_bytes(args: ArgumentTuple) -> bytes | None:
    if "off" not in args.regions:
        ffxiv_exe_filepath = os.path.join(args.working_directory, "ffxiv.exe")
        ffxiv_dx11_exe_filepath = os.path.join(args.working_directory, "ffxiv_dx11.exe")
        if POINTER_SIZE == 4:
            if not os.path.exists(ffxiv_exe_filepath):
                raise RuntimeError("Need ffxiv.exe in the same directory. "
                                   "Copy one from your local Windows/Mac installation.")

            return pathlib.Path(ffxiv_exe_filepath).read_bytes()
        elif POINTER_SIZE == 8:
            if not os.path.exists(ffxiv_dx11_exe_filepath):
                raise RuntimeError("Need ffxiv_dx11.exe in the same directory. "
                                   "Copy one from your local Windows/Mac installation.")

            return pathlib.Path(ffxiv_dx11_exe_filepath).read_bytes()
        else:
            raise RuntimeError("Platform not supported. Only x86 and x64 systems are supported.")
    return None


def setup_cleanup_file(args: ArgumentTuple) -> tuple[str, io.TextIOWrapper]:
    cleanup_dir = pathlib.Path(args.cleanup_directory)

    euid = os.geteuid()
    os.makedirs(cleanup_dir, mode=0o755, exist_ok=True)
    os.chmod(cleanup_dir, 0o755)  # normalize regardless of the inherited umask

    info = os.stat(cleanup_dir, follow_symlinks=False)
    if not stat.S_ISDIR(info.st_mode):
        raise RuntimeError(f"Cleanup directory {cleanup_dir} is not a directory.")

    if info.st_uid != euid:
        raise RuntimeError(f"Cleanup directory {cleanup_dir} is owned by uid {info.st_uid}, not the current "
                           f"uid {euid}; refusing to run scripts from it. Remove it and retry.")
    if info.st_mode & 0o022:
        raise RuntimeError(f"Cleanup directory {cleanup_dir} is writable by group/other "
                           f"(mode {stat.S_IMODE(info.st_mode):04o}); refusing to run scripts from it. "
                           f"Run `chmod 0755 {cleanup_dir}` or remove it and retry.")

    for f in cleanup_dir.iterdir():
        if os.access(f, os.X_OK):
            logging.info(f"Stale cleanup: Running {f.name}")
            with contextlib.suppress(OSError):
                subprocess.call([f.resolve()], shell=True)

    cleanup_file = cleanup_dir / CLEANUP_FILE_NAME
    return (str(cleanup_file.resolve()),
            open(cleanup_file, "w", opener=lambda path, flags: os.open(path, flags, 0o755)))


def wait_for_child_shutdown(pid: int) -> int:
    while True:
        try:
            return os.waitpid(pid, 0)[1]
        except ChildProcessError:
            return 0
        except KeyboardInterrupt:
            break

    with contextlib.suppress(ProcessLookupError):
        os.kill(pid, signal.SIGTERM)

    deadline = time.monotonic() + 5
    killed = False
    while True:
        try:
            reaped, status = os.waitpid(pid, os.WNOHANG)
            if reaped != 0:
                return status
            if not killed and time.monotonic() >= deadline:
                killed = True
                with contextlib.suppress(ProcessLookupError):
                    os.kill(pid, signal.SIGKILL)
            time.sleep(0.05)
        except ChildProcessError:
            return 0
        except KeyboardInterrupt:
            with contextlib.suppress(ProcessLookupError):
                os.kill(pid, signal.SIGTERM)
