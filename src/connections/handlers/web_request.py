import contextlib
import datetime
import http.server
import io
import logging
import selectors
import socket
import time
import typing
import urllib.parse

from .base import BaseConnectionHandler
from utils.consts import BLOCKING_IO_ERRORS
from structs.tcp_info import TcpInfo
from utils.ring_byte_buffer import RingByteBuffer

if typing.TYPE_CHECKING:
    from connections.manager import ConnectionManager


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


class WebRequestHandler:
    def __init__(self,
                 owner: BaseConnectionHandler,
                 cm: "ConnectionManager",
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
        stream = max(0, float(qs.get('stream', ["0"])[0]))
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
        while True:
            now = datetime.datetime.now(tz=datetime.timezone.utc).isoformat()
            for sock in self._cm.sockets:
                try:
                    peer_name = sock.getpeername()
                except socket.error:
                    continue
                tcp_info = TcpInfo.from_socket(sock)
                yield from self._writecsv(now, sock.fileno(), *peer_name, *(getattr(tcp_info, x) for x in keys))

            yield from self._sleep(stream)
            if stream <= 0:
                break

    def _route_404(self, request: HTTPRequest, url: urllib.parse.ParseResult, qs):
        yield from self._write(b"HTTP/1.1 404 Not Found\r\n")
        yield from self._write(b"Connection: Close\r\n")
        yield from self._write(b"\r\n")


class WebRequestConnectionHandler(BaseConnectionHandler):
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
