import asyncio
import contextlib
import ipaddress
import logging
import socket
import typing

from utils.misc import format_addr_port

if typing.TYPE_CHECKING:
    from connections.manager import ConnectionManager


async def _try_connect(destination: tuple, iface: str | None) -> tuple[str, socket.socket]:
    af = socket.AF_INET if isinstance(destination[0], ipaddress.IPv4Address) else socket.AF_INET6
    sock = socket.socket(af, socket.SOCK_STREAM, socket.IPPROTO_TCP)
    try:
        sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
        sock.setsockopt(socket.SOL_TCP, socket.TCP_QUICKACK, 1)
        if iface is not None:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, f"{iface}\0".encode())
        sock.setblocking(False)
        await asyncio.get_running_loop().sock_connect(sock, (str(destination[0]), destination[1]))
        return iface or "(default)", sock
    except BaseException:
        sock.close()
        raise


async def connect_racing(destination: tuple, interfaces: list[str]) -> tuple[str, socket.socket]:
    tasks = [asyncio.create_task(_try_connect(destination, iface)) for iface in (interfaces or [None])]
    errors = []
    try:
        pending = set(tasks)
        while pending:
            done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                if task.exception() is None:
                    for t in pending:
                        t.cancel()
                    return task.result()
                else:
                    errors.append(task.exception())
        raise ExceptionGroup("Could not establish any upstream connection", errors)
    except BaseException:
        for t in tasks:
            t.cancel()
        raise


async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    finally:
        with contextlib.suppress(Exception):
            writer.write_eof()


async def handle_forwarding(conn_id: int, cm: "ConnectionManager",
                            down_reader: asyncio.StreamReader, down_writer: asyncio.StreamWriter,
                            destination: tuple, interfaces: list[str]):
    iface, up_sock = await connect_racing(destination, interfaces)
    logging.info(f"[{conn_id:>4}] Connected via {iface} from {format_addr_port(*up_sock.getsockname())}")
    up_reader, up_writer = await asyncio.open_connection(sock=up_sock)
    down_sock = down_writer.get_extra_info('socket')

    try:
        with cm.track_sockets(down_sock, up_sock):
            async with asyncio.TaskGroup() as tg:
                tg.create_task(_pipe(down_reader, up_writer))
                tg.create_task(_pipe(up_reader, down_writer))
    finally:
        up_writer.close()
        with contextlib.suppress(Exception):
            await up_writer.wait_closed()
