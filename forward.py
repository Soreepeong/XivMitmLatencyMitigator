#!/usr/bin/sudo python
import argparse
import contextlib
import ctypes
import dataclasses
import datetime
import errno
import heapq
import http.server
import io
import ipaddress
import logging.handlers
import os
import selectors
import socket
import struct
import sys
import time
import typing
import urllib.parse

SO_ORIGINAL_DST = 80
SCRIPT_DIRECTORY = os.path.dirname(os.path.abspath(__file__))
BLOCKING_IO_ERRORS = {socket.EWOULDBLOCK, socket.EAGAIN, errno.EINPROGRESS}


def get_sysctl(confname):
    return os.popen(f"sysctl {confname}").read().strip().replace(" ", "")


def is_error_nested(e: BaseException, *error_types: type[BaseException]):
    for error_type in error_types:
        if isinstance(e, error_type):
            return e
        if isinstance(e, BaseExceptionGroup):
            for e2 in e.exceptions:
                if isinstance(e2, error_type):
                    return e2
    return None


class HTTPRequest(http.server.BaseHTTPRequestHandler):
    # noinspection PyMissingConstructor
    def __init__(self, request_text: memoryview | bytes | bytearray):
        self.rfile = io.BytesIO(request_text)
        self.raw_requestline = self.rfile.readline()
        self.error_code = self.error_message = None
        self.parse_request()

    def send_error(self, code, message=None, explain=None):
        self.error_code = code
        self.error_message = message


class TcpInfo(ctypes.Structure):
    """TCP_INFO struct in linux 4.2
    see /usr/include/linux/tcp.h for details"""

    __u8 = ctypes.c_uint8
    __u16 = ctypes.c_uint16
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

        ("tcpi_bytes_acked", __u64),
        ("tcpi_bytes_received", __u64),
        ("tcpi_segs_out", __u32),
        ("tcpi_segs_in", __u32),

        ("tcpi_notsent_bytes", __u32),
        ("tcpi_min_rtt", __u32),
        ("tcpi_data_segs_in", __u32),
        ("tcpi_data_segs_out", __u32),

        ("tcpi_delivery_rate", __u64),

        ("tcpi_busy_time", __u64),
        ("tcpi_rwnd_limited", __u64),
        ("tcpi_sndbuf_limited", __u64),

        ("tcpi_delivered", __u32),
        ("tcpi_delivered_ce", __u32),

        ("tcpi_bytes_sent", __u64),
        ("tcpi_bytes_retrans", __u64),
        ("tcpi_dsack_dups", __u32),
        ("tcpi_reord_seen", __u32),

        ("tcpi_rcv_ooopack", __u32),

        ("tcpi_snd_wnd", __u32),
        ("tcpi_rcv_wnd", __u32),

        ("tcpi_rehash", __u32),

        ("tcpi_total_rto", __u16),
        ("tcpi_total_rto_recoveries", __u16),
        ("tcpi_total_rto_time", __u32),
        ("tcpi_received_ce", __u32),
        ("tcpi_delivered_e1_bytes", __u32),
        ("tcpi_delivered_e0_bytes", __u32),
        ("tcpi_delivered_ce_bytes", __u32),
        ("tcpi_received_e1_bytes", __u32),
        ("tcpi_received_e0_bytes", __u32),
        ("tcpi_received_ce_bytes", __u32),
        ("tcpi_accecn_fail_mode", __u16),
        ("tcpi_accecn_opt_seen", __u16),
    ]

    del __u8, __u16, __u32, __u64

    def __repr__(self):
        keyval = ["{}={!r}".format(x[0], getattr(self, x[0]))
                  for x in self._fields_]
        fields = ", ".join(keyval)
        return "{}({})".format(self.__class__.__name__, fields)

    @classmethod
    def from_socket(cls, sock: socket.socket):
        buf = bytearray(ctypes.sizeof(TcpInfo))
        data = sock.getsockopt(socket.SOL_TCP, socket.TCP_INFO, len(buf))
        buf[:len(data)] = data
        return cls.from_buffer(buf)


@dataclasses.dataclass
class ArgumentTuple:
    targets: list[str] = dataclasses.field(default_factory=list)
    firewall: str = "none"
    listen: str = "0.0.0.0:0"
    write_sysctl: bool = False


class RootRequiredError(RuntimeError):
    pass


class RingByteBuffer:
    def __init__(self, size: int):
        self._buffer = bytearray(size)
        self._buflen = size
        self._pos = 0
        self._len = 0
        self._err: Exception | None = None

    def __len__(self):
        return self._len

    def __bool__(self):
        return bool(self._len)

    @property
    def error(self):
        return self._err

    @property
    def is_complete(self):
        return self._err and not self._len

    def close(self, err: Exception | None = None, *, drain: bool = False):
        self._err = err or EOFError()
        if drain:
            self.drain()

    def drain(self):
        self._len = self._pos = 0

    def get_write_buffer(self) -> memoryview:
        if self._err:
            raise EOFError from self._err
        w = self._pos + self._len
        if w < self._buflen:
            return memoryview(self._buffer)[w:]
        else:
            return memoryview(self._buffer)[w - self._buflen:self._pos]

    def commit_write(self, written: int):
        if self._err:
            raise EOFError from self._err
        if self._len + written > self._buflen:
            raise BufferError("Would cause buffer overflow")
        self._len += written
        return written

    def get_read_buffer(self) -> memoryview:
        w = self._pos + self._len
        if w <= self._buflen:
            return memoryview(self._buffer)[self._pos:w]
        else:
            return memoryview(self._buffer)[self._pos:]

    def commit_read(self, read: int):
        if read > self._len:
            raise BufferError("Would cause buffer underflow")
        if self._len == read:
            self.drain()
        else:
            self._len -= read
            self._pos = (self._pos + self._buflen - read) % self._buflen


class BaseConnection:
    def close(self):
        raise NotImplementedError

    @property
    def closed(self) -> bool:
        raise NotImplementedError

    @property
    def sockets(self) -> typing.Iterable[socket.socket]:
        raise NotImplementedError


class ConnectionManager:
    def __init__(self, listener: socket.socket, args: ArgumentTuple):
        self._listener = listener
        self._selector = selectors.DefaultSelector()
        self._args = args
        self._connections = set[BaseConnection]()
        self._conn_id_counter = 0
        self._timers = list[ConnectionManager._TimerEntry]()
        self._closed = True

    @property
    def closed(self):
        return self._closed

    @property
    def sockets(self):
        yield self._listener
        for c in self._connections:
            yield from c.sockets

    def serve_forever(self):
        while True:
            while self._timers:
                timeout = self._timers[0].timeout - time.time()
                if timeout > 0:
                    break

                item: ConnectionManager._TimerEntry = heapq.heappop(self._timers)
                if item.instance.closed:
                    continue
                try:
                    item.callback()
                except BaseException as e:
                    self._error(item.instance, e)
            else:
                timeout = None

            for fd, ev in self._selector.select(timeout):
                instance, handler = fd.data
                if instance.closed:
                    continue
                try:
                    handler(ev)
                except BaseException as e:
                    self._error(instance, e)

    def wait_until(self, when: float, owner: BaseConnection, callback: typing.Callable[[], None]):
        heapq.heappush(self._timers, ConnectionManager._TimerEntry(when, owner, callback))

    def update_statistics(self):
        for c in self._connections:
            if isinstance(c, ForwardingConnection):
                c.update_statistics()

    def _error(self, instance, e: BaseException):
        assert isinstance(instance, BaseConnection)
        err: EOFError | StopIteration | None = is_error_nested(e, EOFError, StopIteration)
        if err:
            logging.info(f"{instance} ended")
        else:
            err: socket.error | None = is_error_nested(e, socket.error)
            if err:
                logging.error(f"{instance} broken; errno {err.errno}: {err.strerror}")
            else:
                logging.error(f"{instance} broken", exc_info=True)
        instance.close()
        self._connections.remove(instance)

    def _handle(self, ev: int):
        if ev & selectors.EVENT_READ:
            down_addr = "<?>"
            try:
                sock, down_addr = self._listener.accept()
                conn_id = self._conn_id_counter
                self._conn_id_counter += 1
                srv_port, srv_ip = struct.unpack("!2xH4s8x", sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16))
                srv_ip = socket.inet_ntoa(srv_ip)
                local_addr = sock.getsockname()
                up_addr = srv_ip, srv_port

                if local_addr == up_addr:
                    logging.info(f"[{conn_id:>4}] " + " > ".join(f"{x[0]}:{x[1]}" for x in (down_addr, up_addr)))
                    self._connections.add(WebRequestConnection(self, conn_id, sock, down_addr, self._selector))
                else:
                    logging.info(f"[{conn_id:>4}] " +
                                 " > ".join(f"{x[0]}:{x[1]}" for x in (down_addr, local_addr, up_addr)))
                    self._connections.add(ForwardingConnection(conn_id, sock, down_addr, up_addr, self._selector))
            except:
                logging.error(f"Failed to accept from {down_addr}", exc_info=True)
                return

    def __enter__(self):
        self._selector.register(self._listener, selectors.EVENT_READ, (self, self._handle))
        self._closed = False
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._closed = True
        self._selector.unregister(self._listener)
        self._listener.close()

        for conn in self._connections:
            conn.close()
        self._connections.clear()

    @dataclasses.dataclass(order=True)
    class _TimerEntry:
        timeout: float
        instance: BaseConnection = dataclasses.field(compare=False)
        callback: typing.Callable[[], None] = dataclasses.field(compare=False)


class WebRequestHandler:
    def __init__(self,
                 owner: BaseConnection,
                 cm: ConnectionManager,
                 wbuf: RingByteBuffer,
                 wbuf_callback: typing.Callable[[], None],
                 encoding: str = "utf-8",
                 newline: str = "\r\n"):
        self._cm = cm
        self._owner = owner
        self._wbuf = wbuf
        self._flush_callback = wbuf_callback
        self._encoding = encoding
        self._newline = newline.encode(self._encoding)
        self._data = bytearray()
        self._exec = self._handle()
        self._exec.send(None)

    def step(self, recv: bytes | bytearray | memoryview | None = None):
        self._exec.send(recv)

    def throw(self, err: BaseException):
        self._exec.throw(err)

    def _yield(self):
        recv = yield
        if recv is None:
            return
        if not recv:
            raise EOFError
        if len(self._data) + len(recv) > 32768:
            raise OverflowError
        self._data.extend(recv)

    def _flush(self):
        if self._wbuf:
            self._flush_callback()
            yield from self._yield()

    def _write(self, *chunks):
        for chunk in chunks:
            if not chunk:
                continue
            if isinstance(chunk, (bytes, bytearray)):
                chunk = memoryview(chunk)
            elif isinstance(chunk, memoryview):
                pass
            else:
                chunk = memoryview(str(chunk).encode(self._encoding))

            while chunk:
                while True:
                    buf = self._wbuf.get_write_buffer()
                    if buf:
                        break
                    yield from self._flush()

                wlen = min(len(buf), len(chunk))
                buf[:wlen] = chunk[:wlen]
                chunk = chunk[wlen:]
                self._wbuf.commit_write(wlen)

    def _writeline(self, *chunks):
        yield from self._write(*chunks, self._newline)

    def _writecsv(self, *args):
        for i, arg in enumerate(args):
            if i != 0:
                yield from self._write(b",")
            if isinstance(arg, str) and ('"' in arg or ',' in arg):
                yield from self._write(b'"', arg.replace('"', '""'), b'"')
            else:
                yield from self._write(arg)
        yield from self._writeline()

    def _sleep(self, duration: float):
        yield from self._flush()
        timeout = time.time() + duration
        while timeout > time.time():
            self._cm.wait_until(timeout, self._owner, self.step)
            yield from self._yield()

    def _handle(self):
        while True:
            yield from self._yield()
            header_end = self._data.index(b"\r\n\r\n")
            if header_end != -1:
                break

        request = HTTPRequest(self._data[:header_end])
        url = urllib.parse.urlparse(request.path)
        qs = urllib.parse.parse_qs(url.query)
        logging.info(f"{self._owner} {request.command} {request.path}")
        if url.path in ("/stats", "/stats.csv"):
            yield from self._route_stats(request, url, qs)
        else:
            yield from self._route_404(request, url, qs)
        yield from self._flush()

    def _route_stats(self, request: HTTPRequest, url: urllib.parse.ParseResult, qs):
        interval = max(0.1, float(qs.get('interval', ["1"])[0]))
        keys = [x for x in dir(TcpInfo()) if x.startswith("tcpi_")]
        if "cols" in qs:
            cols = [y for x in qs["cols"] for y in x.split(",")]
            keys = [x for x in cols if x in keys]

        yield from self._write(b"HTTP/1.1 200 OK\r\n")
        yield from self._write(b"Connection: Close\r\n")
        if url.path.endswith(".csv"):
            yield from self._write(b"Content-Type: text/csv; charset=utf-8\r\n")
        else:
            yield from self._write(b"Content-Type: text/plain; charset=utf-8\r\n")
        yield from self._write(b"\r\n")

        yield from self._writecsv("time", "fd", "peer_ip", "peer_port", *keys)
        for _ in iter(int, 1) if "stream" in qs else range(1):
            now = datetime.datetime.now(tz=datetime.timezone.utc).isoformat()
            for sock in self._cm.sockets:
                try:
                    peer_name = sock.getpeername()
                except socket.error:
                    continue
                tcp_info = TcpInfo.from_socket(sock)
                yield from self._writecsv(now, sock.fileno(), *peer_name, *(getattr(tcp_info, x) for x in keys))
            yield from self._sleep(interval)

    def _route_404(self, request: HTTPRequest, url: urllib.parse.ParseResult, qs):
        yield from self._write(b"HTTP/1.1 404 Not Found\r\n")
        yield from self._write(b"Connection: Close\r\n")
        yield from self._write(b"\r\n")


class WebRequestConnection(BaseConnection):
    def __init__(self,
                 cm: "ConnectionManager",
                 conn_id: int,
                 sock: socket.socket,
                 addr: tuple[str, int],
                 selector: selectors.BaseSelector):
        self._cm = cm
        self._conn_id = conn_id
        self._sock = sock
        self._addr = addr
        self._selector = selector
        self._closed = False
        self._wbuf = RingByteBuffer(16384)
        self._event_in = True
        self._event_out = False

        with contextlib.ExitStack() as self._cleanup:
            def set_closed():
                self._closed = True

            self._cleanup.callback(set_closed)

            self._cleanup.push(sock)
            sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
            sock.setsockopt(socket.SOL_TCP, socket.TCP_QUICKACK, 1)
            sock.setblocking(False)

            selector.register(sock, selectors.EVENT_READ, (self, self._handle))
            self._cleanup.callback(selector.unregister, sock)

            self._request_handler = WebRequestHandler(self, cm, self._wbuf,
                                                      lambda: self._modify_selector(event_out=True))

            self._cleanup = self._cleanup.pop_all()

    def __str__(self):
        return f"[{self._conn_id:>4}]"

    @property
    def closed(self):
        return self._closed

    @property
    def sockets(self):
        yield self._sock

    def close(self):
        try:
            self._request_handler.throw(EOFError())
        except:
            pass
        self._cleanup.close()

    def _handle(self, ev: int) -> None:
        if self._closed:
            return

        try:
            if ev & selectors.EVENT_READ:
                try:
                    recv = self._sock.recv(8192)
                    if recv and self._request_handler is None:
                        self._request_handler = WebRequestHandler(
                            self,
                            self._cm,
                            self._wbuf,
                            lambda: self._modify_selector(event_out=True))
                    elif not recv and self._request_handler is None:
                        raise EOFError
                    self._request_handler.step(recv)
                except socket.error as e:
                    if e.errno not in BLOCKING_IO_ERRORS:
                        raise

            if ev & selectors.EVENT_WRITE:
                if self._wbuf:
                    try:
                        while True:
                            buf = self._wbuf.get_read_buffer()
                            if not buf:
                                return

                            self._modify_selector(event_out=True)
                            send_len = self._sock.send(buf)
                            self._wbuf.commit_read(send_len)
                    except socket.error as e:
                        if e.errno not in BLOCKING_IO_ERRORS:
                            raise
                else:
                    self._modify_selector(event_out=False)
                    if self._wbuf.error:
                        raise self._wbuf.error
                    elif self._request_handler is not None:
                        self._request_handler.step()
        except BaseException as e:
            if self._request_handler is not None:
                self._request_handler.throw(e)
            raise

    def _modify_selector(self, event_in: bool | None = None, event_out: bool | None = None):
        changed = False
        if event_in is not None and event_in != self._event_in:
            self._event_in = event_in
            changed = True
        if event_out is not None and event_out != self._event_out:
            self._event_out = event_out
            changed = True

        if changed:
            eventmask = (
                    0
                    | (selectors.EVENT_READ if self._event_in else 0)
                    | (selectors.EVENT_WRITE if self._event_out else 0)
            )
            self._selector.modify(self._sock, eventmask, (self, self._handle))


class ForwardingConnection(BaseConnection):
    def __init__(self,
                 conn_id: int,
                 sock: socket.socket,
                 source: typing.Tuple[str, int],
                 destination: typing.Tuple[str, int],
                 selector: selectors.BaseSelector):
        self._conn_id = conn_id
        self._selector = selector
        self._closed = False
        self._source = source
        self._destination = destination

        with contextlib.ExitStack() as self._cleanup:
            def set_closed():
                self._closed = True

            self._cleanup.callback(set_closed)

            self._cleanup.push(sock)
            sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._cleanup.push(sock2)

            self._down = ForwardingConnection.Endpoint(self, "down", sock, True, False, self._handle_down)
            self._up = ForwardingConnection.Endpoint(self, "up", sock2, True, True, self._handle_up)

            try:
                self._up.sock.connect((str(self._destination[0]), self._destination[1]))
            except socket.error as e:
                if e.errno not in BLOCKING_IO_ERRORS:
                    raise

            self._cleanup = self._cleanup.pop_all()

    def __str__(self):
        return f"[{self._conn_id:>4}]"

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
            logging.info(f"{self} Connection established")
            self._down.modify_selector(True, False)
            self._up.modify_selector(True, False, self._handle_up)

    class Endpoint:
        def __init__(self,
                     owner: "ForwardingConnection",
                     channel: str,
                     sock: socket.socket,
                     event_in: bool,
                     event_out: bool,
                     event_cb: typing.Callable[[int], None]):
            self.sock = sock
            self._owner = owner
            self._buffer = RingByteBuffer(65536)
            self._event_in = event_in
            self._event_out = event_out
            self._event_cb = event_cb
            self._channel = channel

            self._last_tcpi = TcpInfo()

            sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
            sock.setsockopt(socket.SOL_TCP, socket.TCP_QUICKACK, 1)
            sock.setblocking(False)
            self._owner._selector.register(sock, (
                    0
                    | (selectors.EVENT_READ if event_in else 0)
                    | (selectors.EVENT_WRITE if event_out else 0)
            ), (owner, event_cb))
            owner._cleanup.callback(self._owner._selector.unregister, sock)

        def __str__(self):
            return f"[{self._owner._conn_id:>4}:{self._channel}]"

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
                    f"{self} Lost packets: {lost} RTT: {round(tcpi.tcpi_rtt / 1000)} var {round(tcpi.tcpi_rttvar / 1000)}")

        def handle(self, ev: int, target: "ForwardingConnection.Endpoint"):
            # self -> target
            if ev & selectors.EVENT_READ and not self._buffer.error:
                try:
                    write_space = self._buffer.get_write_buffer()
                    if not write_space:
                        self.modify_selector(event_in=False)
                    elif self._buffer.commit_write(self.sock.recv_into(write_space, len(write_space))):
                        self._forward_to(target)
                    else:
                        self._buffer.close()
                except socket.error as e:
                    if e.errno not in BLOCKING_IO_ERRORS:
                        self.modify_selector(event_in=False)
                        self._buffer.close(e, drain=True)

                if self._buffer.is_complete:
                    target.sock.shutdown(socket.SHUT_WR)

            # target -> self
            if ev & selectors.EVENT_WRITE:
                if target._buffer:
                    try:
                        target._forward_to(self)
                    except socket.error as e:
                        if e.errno not in BLOCKING_IO_ERRORS:
                            target._buffer.close(e, drain=True)
                            target.modify_selector(event_in=False)
                else:
                    self.modify_selector(event_out=False)
                    if target._buffer.error:
                        self.sock.shutdown(socket.SHUT_WR)

            if self._buffer.is_complete and target._buffer.is_complete:
                raise ExceptionGroup("Both socket closed", (self._buffer.error, target._buffer.error))

        def modify_selector(self,
                            event_in: bool | None = None,
                            event_out: bool | None = None,
                            new_cb: typing.Callable[[int], None] = None):
            changed = False
            if event_in is not None and event_in != self._event_in:
                self._event_in = event_in
                changed = True
            if event_out is not None and event_out != self._event_out:
                self._event_out = event_out
                changed = True
            if new_cb is not None and new_cb != self._event_cb:
                self._event_cb = new_cb
                changed = True

            if changed:
                eventmask = (
                        0
                        | (selectors.EVENT_READ if self._event_in else 0)
                        | (selectors.EVENT_WRITE if self._event_out else 0)
                )
                self._owner._selector.modify(self.sock, eventmask, (self._owner, self._event_cb))

        def _forward_to(self, target: "ForwardingConnection.Endpoint"):
            while True:
                buf = self._buffer.get_read_buffer()
                if not buf:
                    return

                target.modify_selector(event_out=True)
                send_len = target.sock.send(buf)
                self._buffer.commit_read(send_len)


def setup_nftables(targets: list[ipaddress.IPv4Network], addr: str, port: int):
    rules = list[str]()
    for target in targets:
        rules.append(f"ip nat PREROUTING meta l4proto tcp ip daddr {target} dnat {addr}:{port}")
    if addr == "0.0.0.0":
        rules.append(f"ip filter INPUT ip tcp dport {port} accept")
    else:
        rules.append(f"ip filter INPUT ip daddr {addr} tcp dport {port} accept")

    for rule in rules:
        cmd = f"nft -a -e add rule {rule}"
        logging.info(f"Running: {cmd}")
        res = os.popen(cmd)
        h = res.read().strip().split("\n")[0].split(" ")[-1]
        if res.close():
            raise RootRequiredError
        yield f"nft delete rule {' '.join(rule.split(' ')[:3])} handle {h}\n"


def setup_iptables(targets: list[ipaddress.IPv4Network], addr: str, port: int):
    rules = list[str]()
    for target in targets:
        rules.append(f"PREROUTING -t nat -p tcp -d {target} -j DNAT --to-destination {addr}:{port}")
    if addr == "0.0.0.0":
        rules.append(f"INPUT -t filter -p tcp --dport {port} -j ACCEPT")
    else:
        rules.append(f"INPUT -t filter -p tcp -d {addr} --dport {port} -j ACCEPT")

    for rule in rules:
        cmd = f"iptables -I {rule}"
        logging.info(f"Running: iptables -I {rule}")
        if os.system(cmd):
            raise RootRequiredError
        yield f"iptables -D {rule}\n"


def __main__() -> int:
    if sys.version_info < (3, 8):
        print("This script requires at least python 3.8")
        return -1

    logging.basicConfig(level=logging.INFO, force=True,
                        format="%(asctime)s\t%(process)d(main)\t%(levelname)s\t%(message)s",
                        handlers=[
                            logging.StreamHandler(sys.stderr),
                        ])

    parser = argparse.ArgumentParser("test")
    defaults = ArgumentTuple()
    parser.add_argument("-t", "--target", action="append", dest="targets", default=defaults.targets)
    parser.add_argument("-l", "--listen", action="store", dest="listen", default=defaults.listen)
    parser.add_argument("-f", "--firewall", action="store", dest="firewall", default=defaults.firewall,
                        choices=["none", "iptables", "nftables"])
    parser.add_argument("--no-sysctl", action="store_false", dest="write_sysctl", default=defaults.write_sysctl)

    args: ArgumentTuple | argparse.Namespace = parser.parse_args()

    if len(args.targets) == 0:
        logging.error("No targets specified")
        return -1

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_address, listen_port, *_ = f"{args.listen}:0".split(":")
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((listen_address, int(listen_port)))
    listen_port = listener.getsockname()[1]

    err = 0
    is_child = False
    cleanup_filepath = os.path.join(SCRIPT_DIRECTORY, ".cleanup.sh")
    if os.path.exists(cleanup_filepath):
        os.system(cleanup_filepath)

    try:
        targets = []
        for target in args.targets:
            if "/" in target:
                host, prefix_length = target.split("/")
            else:
                host, prefix_length = target, 32

            targets.extend(ipaddress.IPv4Network(f"{x}/{prefix_length}", False)
                           for x in socket.gethostbyname_ex(host)[2])

        with open(cleanup_filepath, "w") as fp:
            fp.write("#!/bin/sh\n")
            match args.firewall:
                case "nftables":
                    fp.writelines(setup_nftables(targets, listen_address, listen_port))
                case "iptables":
                    fp.writelines(setup_iptables(targets, listen_address, listen_port))
                case "none":
                    pass
                case _:
                    raise AssertionError

            if args.write_sysctl:
                fp.write(f"sysctl -w {get_sysctl("sysctl net.ipv4.ip_forward")}\n")
                os.system("sysctl -w net.ipv4.ip_forward=1")

                fp.write(f"sysctl -w {get_sysctl("sysctl net.ipv4.conf.all.route_localnet")}\n")
                os.system("sysctl -w net.ipv4.conf.all.route_localnet=1")

        os.chmod(cleanup_filepath, 0o777)

        listener.listen()
        logging.info(f"Listening on {listener.getsockname()}...")
        logging.info("Press Ctrl+C to quit.")

        with ConnectionManager(listener, args) as manager:
            manager.serve_forever()

    except RootRequiredError:
        logging.error("This program requires root permissions.\n")
        err = -1

    except KeyboardInterrupt:
        pass

    finally:
        if not is_child:
            logging.info("Cleaning up...")
            if os.path.exists(cleanup_filepath):
                os.system(cleanup_filepath)
                os.remove(cleanup_filepath)
            if err:
                logging.error("One or more error have occurred during cleanup.")
                err = -1
            else:
                logging.info("Cleanup complete.")
    return err


if __name__ == "__main__":
    exit(__main__())
