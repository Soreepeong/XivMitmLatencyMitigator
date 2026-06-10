import asyncio
import contextlib
import ctypes
import ipaddress
import logging
import socket
import typing

from connections.handlers.forwarding import handle_forwarding
from connections.handlers.forwarding_xiv import ForwardingXivHandler
from connections.handlers.web_request import handle_web_request
from utils.consts import SO_ORIGINAL_DST, IP6T_SO_ORIGINAL_DST, NAT64_NETWORK
from utils.exceptions import find_nested_error, CONNECTION_ERRORS
from utils.icmp_race import FindBestInterfaceConfig
from utils.interop.socket import sockaddr_in, sockaddr_in6
from utils.interop.xivalex import MitigationConfig
from utils.misc import format_addr_port_tuples, to_ip_address_and_port

if typing.TYPE_CHECKING:
    from utils.interop.xiv_network import XivBundleHeader, XivMessageHeader


class _FfxivObserver:
    _SENTINEL = object()

    def __init__(self, limit: int = 1000):
        self._q: asyncio.Queue = asyncio.Queue(limit)
        self._broken = False

    def put_nowait(self, item):
        try:
            self._q.put_nowait(item)
        except asyncio.QueueFull:
            self._q.shutdown(True)

    async def get(self):
        item = await self._q.get()
        if item is self._SENTINEL:
            raise ConnectionAbortedError("too many pending messages")
        return item


class ConnectionManager:
    def __init__(self, listeners: list[socket.socket], upstream_interfaces: list[str], enable_web: bool, nat64: str,
                 xivalex_mitigation_config: MitigationConfig,
                 icmp_config: FindBestInterfaceConfig | None = None):
        self._listeners = listeners
        self._upstream_interfaces = upstream_interfaces
        self._enable_web = enable_web
        self._nat64 = nat64
        self._xivalex = xivalex_mitigation_config
        self._icmp_config = icmp_config
        self._conn_id_counter = 0
        self._active_sockets: set[socket.socket] = set()
        self._ffxiv_packet_observers: set[asyncio.Queue] = set()

    @property
    def tracked_sockets(self):
        yield from self._listeners
        yield from self._active_sockets

    @contextlib.contextmanager
    def ffxiv_packet_observer(self, limit: int = 1000):
        obs = asyncio.Queue(limit)
        self._ffxiv_packet_observers.add(obs)
        try:
            yield obs
        finally:
            obs.shutdown(True)
            self._ffxiv_packet_observers.discard(obs)

    def notify_ffxiv_observers(self, sock: socket.socket, direction: str,
                               bundle_header: "XivBundleHeader", message_header: "XivMessageHeader",
                               message_data: bytes):
        if not self._ffxiv_packet_observers:
            return
        item = (sock, direction, bundle_header.timestamp, bundle_header.conn_type, message_header,
                bytearray(message_data))
        for obs in self._ffxiv_packet_observers:
            obs.put_nowait(item)

    @contextlib.contextmanager
    def track_sockets(self, *socks: socket.socket):
        self._active_sockets.update(socks)
        try:
            yield
        finally:
            for s in socks:
                self._active_sockets.discard(s)

    async def _handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self._conn_id_counter += 1
        conn_id = self._conn_id_counter

        sock: socket.socket = writer.get_extra_info('socket')
        down_addr = to_ip_address_and_port(writer.get_extra_info('peername'))
        local_addr = to_ip_address_and_port(writer.get_extra_info('sockname'))
        up_addr = local_addr

        try:
            match sock.family:
                case socket.AF_INET:
                    original_dst = sockaddr_in.from_buffer_copy(
                        sock.getsockopt(socket.IPPROTO_IP, SO_ORIGINAL_DST, ctypes.sizeof(sockaddr_in)))
                    up_addr = ipaddress.IPv4Address(bytes(original_dst.sin_addr)), int(original_dst.sin_port)
                    if self._nat64 == "wrap":
                        up_addr = ipaddress.IPv6Address(int(up_addr[0]) + int(NAT64_NETWORK)), *up_addr[1:]
                case socket.AF_INET6:
                    try:
                        original_dst = sockaddr_in6.from_buffer_copy(
                            sock.getsockopt(socket.IPPROTO_IPV6, IP6T_SO_ORIGINAL_DST, ctypes.sizeof(sockaddr_in6)))
                        up_addr = (
                            ipaddress.IPv6Address(bytes(original_dst.sin6_addr)),
                            int(original_dst.sin6_port),
                            int(original_dst.sin6_flowinfo),
                            int(original_dst.sin6_scope_id),
                        )
                        if up_addr[0] in NAT64_NETWORK and self._nat64 == "unwrap":
                            up_addr = ipaddress.IPv4Address(int(up_addr[0]) - int(NAT64_NETWORK)), *up_addr[1:]
                    except FileNotFoundError:
                        up_addr = local_addr
                case _:
                    raise AssertionError

            if local_addr != up_addr:
                logging.info(f"[{conn_id:>4}] " + format_addr_port_tuples(down_addr, local_addr, up_addr, sep=" > "))
                if definitions := [f for f in self._xivalex.definitions if f.is_applicable(*up_addr)]:
                    handler = ForwardingXivHandler(
                        conn_id, self,
                        MitigationConfig(self._xivalex.dry_run,
                                         self._xivalex.measure_ping,
                                         self._xivalex.extra_delay,
                                         definitions))
                    await handler.handle(reader, writer, up_addr, self._upstream_interfaces, self._icmp_config)
                else:
                    await handle_forwarding(conn_id, self, reader, writer, up_addr, self._upstream_interfaces,
                                            self._icmp_config)
            elif self._enable_web:
                logging.info(f"[{conn_id:>4}] " + format_addr_port_tuples(down_addr, up_addr, sep=" > "))
                await handle_web_request(conn_id, self, reader, writer)
            else:
                logging.info(f"Rejected " + format_addr_port_tuples(down_addr, up_addr, sep=" > "))

        except Exception as e:
            err = find_nested_error(e, *CONNECTION_ERRORS)
            if err:
                return

            err = find_nested_error(e, OSError)
            if err:
                logging.error(f"[{conn_id:>4}] broken: {err}")
                return

            logging.error(f"[{conn_id:>4}] broken", exc_info=True)

        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

            logging.info(f"[{conn_id:>4}] ended")

    async def serve_forever(self):
        servers: list[asyncio.Server] = []
        try:
            for listener in self._listeners:
                servers.append(await asyncio.start_server(self._handle_connection, sock=listener))
            async with asyncio.TaskGroup() as tg:
                for server in servers:
                    tg.create_task(server.serve_forever())
        finally:
            for server in servers:
                server.close()
            for listener in self._listeners:
                with contextlib.suppress(Exception):
                    listener.close()
            self._listeners.clear()
