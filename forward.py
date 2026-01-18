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


def is_error_nested(e: BaseException, *error_types: type[BaseException]):
    for error_type in error_types:
        if isinstance(e, error_type):
            return e
        if isinstance(e, BaseExceptionGroup):
            for e2 in e.exceptions:
                if isinstance(e2, error_type):
                    return e2
    return None


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
    nftables: bool = False
    listen: str = "0.0.0.0:0"
    write_sysctl: bool = True


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


class ConnectionManager:
    def __init__(self, listener: socket.socket, args: ArgumentTuple):
        self._listener = listener
        self._selector = selectors.DefaultSelector()
        self._args = args
        self._connections = set[BaseConnection]()
        self._conn_id_counter = 0
        self._timers = list[ConnectionManager._TimerEntry]()

    def enumerate_statistics(self):
        for c in self._connections:
            if isinstance(c, ForwardingConnection):
                yield c._up.sock.getpeername(), c._up.get_tcp_info()
                yield c._down.sock.getpeername(), c._down.get_tcp_info()

    def next_timeout(self) -> float | None:
        return None

    def serve_forever(self):
        while True:
            now = time.time()
            while self._timers:
                timeout = self._timers[0].timeout - now
                if timeout > 0:
                    break
                item: ConnectionManager._TimerEntry = heapq.heappop(self._timers)
                try:
                    item.callback()
                except BaseException as e:
                    self._error(item.instance, e)
            else:
                timeout = None

            for fd, ev in self._selector.select(timeout):
                instance, handler = fd.data
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
                    logging.info(" > ".join(f"{x[0]}:{x[1]}" for x in (down_addr, up_addr)))
                    self._connections.add(WebRequestConnection(self, conn_id, sock, down_addr, self._selector))
                else:
                    logging.info(" > ".join(f"{x[0]}:{x[1]}" for x in (down_addr, local_addr, up_addr)))
                    self._connections.add(
                        ForwardingConnection(conn_id, self._args, sock, down_addr, up_addr, self._selector))
            except:
                logging.error(f"Failed to accept from {down_addr}", exc_info=True)
                return

    def __enter__(self):
        self._selector.register(self._listener, selectors.EVENT_READ, (self, self._handle))
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
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
        self._request_handler = None

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

            self._cleanup = self._cleanup.pop_all()

    def __str__(self):
        return f"[{self._conn_id:>4}]"

    def close(self):
        self._cleanup.close()

    def _handle_request(self):
        gen = yield

        header = bytearray()
        header_end = -1
        while True:
            recv = yield
            if recv is None:
                continue
            header.extend(recv)
            header_end = header.index(b"\r\n\r\n")
            if header_end != -1:
                break
            if len(recv) == 0:
                raise EOFError("No header received")

        request = WebRequestConnection._HTTPRequest(header[:header_end])

        def write(data: memoryview | bytes | bytearray | None = None):
            if not data:
                if self._wbuf:
                    self._modify_selector(event_out=True)
                    yield
                return

            if not isinstance(data, memoryview):
                data = memoryview(data)

            while data:
                while True:
                    buf = self._wbuf.get_write_buffer()
                    if buf:
                        break
                    yield from write()

                wlen = min(len(buf), len(data))
                buf[:wlen] = data[:wlen]
                data = data[wlen:]
                self._wbuf.commit_write(wlen)

        def write_csv(*args: str):
            for i, arg in enumerate(args):
                if i != 0:
                    yield from write(b",")
                arg = str(arg)
                if '"' in arg or ',' in arg:
                    yield from write(b'"')
                    yield from write(arg.replace('"', '""').encode("utf-8"))
                    yield from write(b'"')
                else:
                    yield from write(arg.encode("utf-8"))
            yield from write(b"\r\n")

        def wake_self():
            if not self._closed:
                gen.send(None)

        def sleep(duration: float):
            yield from write()
            timeout = time.time() + duration
            while timeout > time.time():
                self._cm.wait_until(timeout, self, wake_self)
                yield

        url = urllib.parse.urlparse(request.path)
        qs = urllib.parse.parse_qs(url.query)
        if url.path in ("/stats", "/stats.csv"):
            yield from write(b"HTTP/1.1 200 OK\r\n")
            yield from write(b"Connection: Close\r\n")
            if url.path.endswith(".csv"):
                yield from write(b"Content-Type: text/csv; charset=utf-8\r\n")
            else:
                yield from write(b"Content-Type: text/plain; charset=utf-8\r\n")
            yield from write(b"\r\n")
            keys = [x for x in dir(TcpInfo()) if x.startswith("tcpi_")]
            if "cols" in qs:
                cols = [y for x in qs["cols"] for y in x.split(",")]
                keys = [x for x in cols if x in keys]

            yield from write_csv("time", "peer_ip", "peer_port", *keys)
            for _ in iter(int, 1) if "stream" in qs else range(1):
                now = datetime.datetime.now(tz=datetime.timezone.utc).isoformat()
                for peer_name, tcp_info in self._cm.enumerate_statistics():
                    yield from write_csv(now, *peer_name, *(str(getattr(tcp_info, x)) for x in keys))
                yield from sleep(1)
        else:
            yield from write(b"HTTP/1.1 404 Not Found\r\n")
            yield from write(b"Connection: Close\r\n")
            yield from write(b"\r\n")
        yield from write()

    def _handle(self, ev: int) -> None:
        if self._closed:
            return

        try:
            if ev & selectors.EVENT_READ:
                try:
                    recv = self._sock.recv(8192)
                    if recv and self._request_handler is None:
                        self._request_handler = self._handle_request()
                        self._request_handler.send(None)
                        self._request_handler.send(self._request_handler)
                    elif not recv and self._request_handler is None:
                        raise EOFError
                    self._request_handler.send(recv)
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
                        self._request_handler.send(None)
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

    class _HTTPRequest(http.server.BaseHTTPRequestHandler):
        # noinspection PyMissingConstructor
        def __init__(self, request_text: memoryview | bytes | bytearray):
            self.rfile = io.BytesIO(request_text)
            self.raw_requestline = self.rfile.readline()
            self.error_code = self.error_message = None
            self.parse_request()

        def send_error(self, code, message=None, explain=None):
            self.error_code = code
            self.error_message = message


class ForwardingConnection(BaseConnection):
    def __init__(self,
                 conn_id: int,
                 args: ArgumentTuple,
                 sock: socket.socket,
                 source: typing.Tuple[str, int],
                 destination: typing.Tuple[str, int],
                 selector: selectors.BaseSelector):
        self._conn_id = conn_id
        self._args = args
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
    parser.add_argument("-n", "--nftables", action="store_true", dest="nftables", default=defaults.nftables)
    parser.add_argument("--no-sysctl", action="store_false", dest="write_sysctl", default=defaults.write_sysctl)

    args: ArgumentTuple | argparse.Namespace = parser.parse_args()

    if len(args.targets) == 0:
        logging.error("No targets specified")
        return -1

    logging.info(f"Write sysctl values: {'yes' if args.write_sysctl else 'no'}")

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

    fw_setup_cmds = []
    removal_cmds = []
    try:
        targets = []
        for target in args.targets:
            if "/" in target:
                host, prefix_length = target.split("/")
            else:
                host, prefix_length = target, 32

            targets.extend(ipaddress.IPv4Network(f"{x}/{prefix_length}", False)
                           for x in socket.gethostbyname_ex(host)[2])

        for target in targets:
            if args.nftables:
                rule = f"ip nat PREROUTING meta l4proto tcp ip daddr {target} dnat {listen_address}:{listen_port}"
                fw_setup_cmds.append(f"nft -a -e add rule {rule}")
            else:
                rule = f"-t nat -p tcp -d {target} -j DNAT --to-destination {listen_address}:{listen_port}"
                fw_setup_cmds.append(f"iptables -I PREROUTING {rule}")
                removal_cmds.append(f"iptables -D PREROUTING {rule}")

        if listen_address == "0.0.0.0":
            if args.nftables:
                fw_setup_cmds.append(f"nft -a -e add rule ip filter INPUT ip tcp dport {listen_port} accept")
            else:
                fw_setup_cmds.append(f"iptables -I INPUT -t filter -p tcp --dport {listen_port} -j ACCEPT")
                removal_cmds.append(f"iptables -D INPUT -t filter -p tcp --dport {listen_port} -j ACCEPT")
        else:
            if args.nftables:
                fw_setup_cmds.append(
                    f"nft -a -e add rule ip filter INPUT ip daddr {listen_address} tcp dport {listen_port} accept")
            else:
                fw_setup_cmds.append(
                    f"iptables -I INPUT -t filter -p tcp -d {listen_address} --dport {listen_port} -j ACCEPT")
                removal_cmds.append(
                    f"iptables -D INPUT -t filter -p tcp -d {listen_address} --dport {listen_port} -j ACCEPT")

        with open(cleanup_filepath, "w") as fp:
            fp.write("#!/bin/sh\n")
            fp.writelines(removal_cmds)

        if args.nftables:
            for add_cmd in fw_setup_cmds:
                logging.info(f"Running: {add_cmd}")
                res = os.popen(add_cmd)
                h = res.read().strip().split("\n")[0].split(" ")[-1]
                if res.close():
                    raise RootRequiredError
                removal_cmds.append(f"nft delete rule {' '.join(add_cmd.split(' ')[5:8])} handle {h}")
        else:
            for add_cmd in fw_setup_cmds:
                logging.info(f"Running: {add_cmd}")
                if os.system(add_cmd):
                    raise RootRequiredError

        os.chmod(cleanup_filepath, 0o777)

        if args.write_sysctl:
            removal_cmds.append("sysctl -w " + os.popen("sysctl net.ipv4.ip_forward")
                                .read().strip().replace(" ", ""))
            os.system("sysctl -w net.ipv4.ip_forward=1")

            removal_cmds.append("sysctl -w " + os.popen("sysctl net.ipv4.conf.all.route_localnet")
                                .read().strip().replace(" ", ""))
            os.system("sysctl -w net.ipv4.conf.all.route_localnet=1")
        else:
            logging.info("Skipping sysctl commands.")

        listener.listen(32)
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
            for removal_cmd in removal_cmds:
                logging.info(f"Running: {removal_cmd}")
                exit_code = os.system(removal_cmd)
                if exit_code:
                    logging.warning(f"\t=> Failed with exit code {exit_code}")
                    err = -1
            if os.path.exists(cleanup_filepath):
                os.remove(cleanup_filepath)
            if err:
                logging.error("One or more error have occurred during cleanup.")
                err = -1
            else:
                logging.info("Cleanup complete.")
    return err


if __name__ == "__main__":
    exit(__main__())
