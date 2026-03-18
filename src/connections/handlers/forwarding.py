import contextlib
import ipaddress
import logging
import os
import selectors
import socket
import typing

from structs.tcp_info import TcpInfo
from utils.consts import BLOCKING_IO_ERRORS
from connections.file_bound_selector import FileBoundSelector
from utils.interop.xiv_network import XivBundleHeader
from utils.misc import format_addr_port
from utils.ring_byte_buffer import RingByteBuffer
from .base import BaseConnectionHandler


class EndpointStream:
    def __init__(self,
                 owner: object,
                 selector: selectors.BaseSelector,
                 name: str,
                 event_in: bool,
                 event_out: bool,
                 event_cb: typing.Callable[[int], None],
                 sock: socket.socket | tuple):
        self.sock = sock
        self._name = name
        self._buf_r = RingByteBuffer(XivBundleHeader.MAX_LENGTH)

        self._last_tcpi = TcpInfo()

        with contextlib.ExitStack() as self._cleanup:
            self.sock = self._cleanup.push(sock if isinstance(sock, socket.socket) else socket.socket(*sock))

            self.sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
            self.sock.setsockopt(socket.SOL_TCP, socket.TCP_QUICKACK, 1)
            self.sock.setblocking(False)
            self.selector = self._cleanup.push(
                FileBoundSelector(owner, selector, self.sock, event_in, event_out, event_cb))
            self._cleanup = self._cleanup.pop_all()

    def __str__(self):
        return f"{self._name}"

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._cleanup.close()

    def fileno(self):
        return self.sock.fileno()

    def get_tcp_info(self):
        return TcpInfo.from_socket(self.sock)

    def update_statistics(self):
        tcpi = self.get_tcp_info()
        lost = tcpi.tcpi_lost - tcpi.tcpi_lost
        self._last_tcpi = tcpi
        if lost:
            logging.warning(
                f"[{self}] Lost packets: {lost} RTT: {round(tcpi.tcpi_rtt / 1000)} var {round(tcpi.tcpi_rttvar / 1000)}")

    def handle(self, ev: int, target: "ForwardingConnectionHandler._EndpointStreamImpl"):
        # self -> target
        if ev & selectors.EVENT_READ and not self._buf_r.error:
            try:
                write_space = self._buf_r.get_write_buffer()
                if not write_space:
                    self.selector.modify(event_in=False)
                elif self._buf_r.commit_write(self.sock.recv_into(write_space, len(write_space))):
                    self._forward_to(target)
                else:
                    self._buf_r.close()
            except socket.error as e:
                if e.errno not in BLOCKING_IO_ERRORS:
                    self.selector.modify(event_in=False)
                    self._buf_r.close(e, drain=True)

            if self._buf_r.is_complete:
                target.sock.shutdown(socket.SHUT_WR)

        # target -> self
        if ev & selectors.EVENT_WRITE:
            if target._buf_r:
                try:
                    target._forward_to(self)
                except socket.error as e:
                    if e.errno not in BLOCKING_IO_ERRORS:
                        target._buf_r.close(e, drain=True)
                        target.selector.modify(event_in=False)
            else:
                target.selector.modify(event_in=True)
                self.selector.modify(event_out=False)
                if target._buf_r.error:
                    self.sock.shutdown(socket.SHUT_WR)

        if self._buf_r.is_complete and target._buf_r.is_complete:
            raise ExceptionGroup("Both socket closed", (self._buf_r.error, target._buf_r.error))

    def _forward_to(self, target: "ForwardingConnectionHandler._EndpointStreamImpl"):
        while self._buf_r:
            buf = self._buf_r.get_read_buffer()
            target.selector.modify(event_out=True)
            send_len = target.sock.send(buf)
            self._buf_r.commit_read(send_len)


class ForwardingConnectionHandler(BaseConnectionHandler):
    _EndpointStreamImpl: typing.ClassVar[type[EndpointStream]] = EndpointStream

    def __init_subclass__(cls, endpoint_stream_impl: type["EndpointStream"] | None = None, **kwargs):
        cls._EndpointStreamImpl = endpoint_stream_impl

    def __init__(self,
                 selector: selectors.BaseSelector,
                 conn_id: int,
                 sock: socket.socket,
                 destination: tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int],
                 upstream_interfaces: list[str]):
        self._conn_id = conn_id
        self._closed = False
        self._selector = selector
        self._destination = destination
        self._sock_down = sock
        self._pending_up_socks: list[socket.socket] = []

        af = socket.AF_INET if isinstance(destination[0], ipaddress.IPv4Address) else socket.AF_INET6

        with contextlib.ExitStack() as cleanup:
            cleanup.callback(lambda: setattr(self, '_closed', True))
            cleanup.push(sock)
            cleanup.callback(self._close_pending_up)

            for iface in (upstream_interfaces or [None]):
                sock2 = socket.socket(af, socket.SOCK_STREAM, socket.IPPROTO_TCP)
                sock2.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
                sock2.setsockopt(socket.SOL_TCP, socket.TCP_QUICKACK, 1)
                if iface is not None:
                    sock2.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, f"{iface}\0".encode("utf-8"))
                sock2.setblocking(False)
                try:
                    sock2.connect((str(destination[0]), destination[1]))
                except socket.error as e:
                    if e.errno not in BLOCKING_IO_ERRORS:
                        sock2.close()
                        continue
                self._pending_up_socks.append(sock2)
                selector.register(
                    sock2,
                    selectors.EVENT_READ | selectors.EVENT_WRITE,
                    (self, lambda ev, s=sock2: self._handle_up_candidate(s, ev)),
                )

            if not self._pending_up_socks:
                raise OSError("Could not initiate any upstream connection")

            self._cleanup = cleanup.pop_all()

    def _close_pending_up(self):
        for sock2 in self._pending_up_socks:
            try:
                self._selector.unregister(sock2)
            except:
                pass
            sock2.close()
        self._pending_up_socks.clear()

    def _handle_up_candidate(self, sock2: socket.socket, ev: int):
        if self._closed:
            return

        err = sock2.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        if err:
            self._selector.unregister(sock2)
            self._pending_up_socks.remove(sock2)
            sock2.close()
            if not self._pending_up_socks:
                raise OSError(err, os.strerror(err))
            return

        if not (ev & selectors.EVENT_WRITE):
            return

        iface = sock2.getsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, 16).rstrip(b'\x00').decode() or "(default)"
        sockname = format_addr_port(*sock2.getsockname())
        logging.info(f"[{self}] Connected via {iface} from {sockname}")
        self._selector.unregister(sock2)
        self._pending_up_socks.remove(sock2)
        self._close_pending_up()
        self._complete_init(sock2)

    def _complete_init(self, sock2: socket.socket):
        self._cleanup.push(sock2)

        self._down = self._cleanup.push(self._EndpointStreamImpl(
            self, self._selector, f"{self}:down", True, False, self._handle_down, self._sock_down))
        self._up = self._cleanup.push(self._EndpointStreamImpl(
            self, self._selector, f"{self}:up", True, False, self._handle_up, sock2))

        self._on_complete_init()

    def _on_complete_init(self):
        pass

    def __str__(self):
        return f"{self._conn_id:>4}"

    @property
    def sockets(self):
        if hasattr(self, '_down'):
            yield self._down.sock
            yield self._up.sock
        else:
            yield self._sock_down
            yield from self._pending_up_socks

    @property
    def closed(self):
        return self._closed

    def close(self):
        self._cleanup.close()

    def update_statistics(self):
        if hasattr(self, '_down'):
            self._up.update_statistics()
            self._down.update_statistics()

    def _handle_down(self, ev: int):
        if self._closed:
            return

        self._down.handle(ev, self._up)

    def _handle_up(self, ev: int):
        if self._closed:
            return

        self._up.handle(ev, self._down)
