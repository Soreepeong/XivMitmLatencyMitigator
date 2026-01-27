import contextlib
import ipaddress
import logging
import os
import selectors
import socket
import typing

from utils.interop.xiv_network import XivBundleHeader
from utils.file_bound_selector import FileBoundSelector
from .base import BaseConnectionHandler
from utils.consts import BLOCKING_IO_ERRORS
from structs.tcp_info import TcpInfo
from utils.ring_byte_buffer import RingByteBuffer


class EndpointStream:
    def __init__(self,
                 selector: selectors.BaseSelector,
                 name: str,
                 sock: socket.socket | None,
                 event_in: bool,
                 event_out: bool,
                 event_cb: typing.Callable[[int], None]):
        self.sock = sock
        self._name = name
        self._buf_r = RingByteBuffer(XivBundleHeader.MAX_LENGTH)

        self._last_tcpi = TcpInfo()

        if self.sock is None:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)

        with contextlib.ExitStack() as self._cleanup:
            self._cleanup.push(self.sock)

            self.sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
            self.sock.setsockopt(socket.SOL_TCP, socket.TCP_QUICKACK, 1)
            self.sock.setblocking(False)
            self.selector = self._cleanup.push(FileBoundSelector(selector, self.sock, event_in, event_out, event_cb))
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
                 upstream_interface: str | None):
        selector.owner = self
        self._conn_id = conn_id
        self._closed = False

        with contextlib.ExitStack() as self._cleanup:
            def set_closed():
                self._closed = True

            self._cleanup.callback(set_closed)

            self._down = self._cleanup.push(self._EndpointStreamImpl(
                selector, f"{self}:down", sock, True, False, self._handle_down))
            self._up = self._cleanup.push(self._EndpointStreamImpl(
                selector, f"{self}:up", None, True, True, self._handle_up))

            if upstream_interface is not None:
                self._up.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
                                         f"{upstream_interface}\0".encode("utf-8"))

            try:
                self._up.sock.connect((str(destination[0]), destination[1]))
            except socket.error as e:
                if e.errno not in BLOCKING_IO_ERRORS:
                    raise

            self._cleanup = self._cleanup.pop_all()

    def __str__(self):
        return f"{self._conn_id:>4}"

    @property
    def sockets(self):
        yield self._down.sock
        yield self._up.sock

    @property
    def closed(self):
        return self._closed

    def close(self):
        self._cleanup.close()

    def update_statistics(self):
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

    def _handle_up_initial(self, ev: int):
        if self._closed:
            return

        if ev & selectors.EVENT_READ:
            err = self._up.sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            raise OSError(err, os.strerror(err))

        if ev & selectors.EVENT_WRITE:
            logging.info(f"[{self}] Connection established")
            self._down.selector.modify(True, False)
            self._up.selector.modify(True, False, self._handle_up)
