import asyncio
import contextlib
import ipaddress
import logging
import socket
import time
import typing

from utils.icmp_race import FindBestInterfaceConfig, find_best_interface
from utils.misc import format_addr_port, DummyAsyncClosable

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
        with contextlib.suppress(BaseException):
            sock.close()
        raise


async def _race_connect(destination: tuple, interfaces: list[str | None]) -> tuple[str, socket.socket]:
    tasks = [asyncio.create_task(_try_connect(destination, iface)) for iface in interfaces]
    errors = []
    try:
        for coro in asyncio.as_completed(tasks):
            try:
                return await coro
            except Exception as e:
                errors.append(e)
        raise ExceptionGroup("Could not establish any upstream connection", errors)
    finally:
        for t in tasks:
            t.cancel()


# Most recently measured best interface per destination IP, with a single-flight guard. The game
# opens multiple near-simultaneous connections to one server IP; this lets them share a single ICMP
# probe (instead of each paying the full measurement cost) and ensures they pick the same interface.
_best_iface_cache: dict[str, tuple[str, float]] = {}
_best_iface_inflight: dict[str, "asyncio.Task[str]"] = {}


async def _measure_best_interface(destination_ip: str, interfaces: list[str],
                                  icmp_config: "FindBestInterfaceConfig") -> str:
    cached = _best_iface_cache.get(destination_ip)
    if cached is not None and cached[1] > time.monotonic():
        return cached[0]

    task = _best_iface_inflight.get(destination_ip)
    if task is None:
        async def _run() -> str:
            best = await find_best_interface(
                destination_ip, interfaces,
                num_attempts=icmp_config.num_attempts,
                interval=icmp_config.interval,
                penalties=icmp_config.penalties,
                debug=icmp_config.debug,
            )
            if icmp_config.cache_ttl > 0:
                _best_iface_cache[destination_ip] = (best, time.monotonic() + icmp_config.cache_ttl)
            return best

        def _cleanup(finished: "asyncio.Task[str]") -> None:
            _best_iface_inflight.pop(destination_ip, None)
            if not finished.cancelled():
                finished.exception()  # retrieve so a shared probe failure does not warn at GC time

        task = asyncio.ensure_future(_run())
        _best_iface_inflight[destination_ip] = task
        task.add_done_callback(_cleanup)

    # Shield so a single cancelled connection does not abort the probe shared with the others.
    return await asyncio.shield(task)


async def connect_racing(destination: tuple, interfaces: list[str],
                         icmp_config: "FindBestInterfaceConfig | None" = None) -> tuple[str, socket.socket]:
    candidates: list[str | None] = list(interfaces) if interfaces else [None]

    # With more than one interface, measure latency/jitter with ICMP and connect through the
    # best one, racing the rest only as a fallback. Skip the probe for 0/1 interface (nothing to
    # choose) or non-IPv4 targets (find_best_interface uses IPv4 ICMP echo).
    if (icmp_config is not None and len(candidates) > 1
            and isinstance(destination[0], ipaddress.IPv4Address)):
        destination_ip = str(destination[0])
        try:
            best = await _measure_best_interface(
                destination_ip, [iface for iface in candidates if iface is not None], icmp_config)
        except Exception as e:
            logging.info(f"ICMP interface measurement failed; racing all interfaces: {e}")
        else:
            try:
                return await _try_connect(destination, best)
            except Exception as e:
                logging.info(f"Connecting via measured-best interface {best} failed; racing the rest: {e}")
                _best_iface_cache.pop(destination_ip, None)  # stop recommending a path that won't connect
                candidates = [iface for iface in candidates if iface != best]

    return await _race_connect(destination, candidates)


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
                            destination: tuple, interfaces: list[str],
                            icmp_config: "FindBestInterfaceConfig | None" = None):
    iface, up_sock = await connect_racing(destination, interfaces, icmp_config)
    up_writer = DummyAsyncClosable()
    try:
        logging.info(f"[{conn_id:>4}] Connected via {iface} from {format_addr_port(*up_sock.getsockname())}")
        up_reader, up_writer = await asyncio.open_connection(sock=up_sock)
        down_sock = down_writer.get_extra_info('socket')

        with cm.track_sockets(down_sock, up_sock):
            async with asyncio.TaskGroup() as tg:
                tg.create_task(_pipe(down_reader, up_writer))
                tg.create_task(_pipe(up_reader, down_writer))
    finally:
        with contextlib.suppress(BaseException):
            down_writer.close()
        with contextlib.suppress(BaseException):
            up_writer.close()
        await asyncio.gather(down_writer.wait_closed(), up_writer.wait_closed(), return_exceptions=True)
