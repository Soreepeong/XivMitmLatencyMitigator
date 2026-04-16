import asyncio
import datetime
import http.server
import io
import logging
import socket
import typing
import urllib.parse

from structs.tcp_info import TcpInfo
from utils.http.chunked_stream_writer import ChunkedStreamWriter
from utils.http.decoding_stream_reader import DecodingStreamReader

if typing.TYPE_CHECKING:
    from connections.manager import ConnectionManager

_MAX_HEADER_LENGTH = 32768
_HEADER_TIMEOUT = 30


class HTTPError(Exception):
    status: http.HTTPStatus
    body: bytes
    headers: dict[str, str]

    def __init__(self,
                 status: http.HTTPStatus,
                 body: str | None = None,
                 break_keepalive: bool = False,
                 headers: dict[str, object] | None = None):
        self.status = status
        self.body = (body or status.phrase).encode("utf-8")
        self.break_keepalive = break_keepalive
        self.headers = {
            "content-type": "text/plain; charset=utf-8",
            "content-length": str(len(self.body)),
        }
        if headers:
            for k, v in headers.items():
                match k.lower():
                    case "content-length" | "connection" | "transfer-encoding":
                        raise KeyError(f"{k} must not be specified")
                    case _:
                        self.headers[k] = str(v)


class HTTPRequest(http.server.BaseHTTPRequestHandler):
    # noinspection PyMissingConstructor
    def __init__(self, request_text: memoryview | bytes | bytearray):
        self.rfile = io.BytesIO(request_text)
        self.raw_requestline = self.rfile.readline()
        self.error_code = self.error_message = None
        self.parse_request()
        self.url = urllib.parse.urlparse(self.path)
        self.qs = urllib.parse.parse_qs(self.url.query)

    def send_error(self, code, message=None, explain=None):
        self.error_code = code
        self.error_message = message


def _write_csv_line(writer: asyncio.StreamWriter | ChunkedStreamWriter, *args):
    parts = []
    for arg in args:
        s = str(arg)
        if '"' in s or ',' in s:
            s = '"' + s.replace('"', '""') + '"'
        parts.append(s)
    writer.write((",".join(parts) + "\r\n").encode("utf-8"))


def _write_header(writer: asyncio.StreamWriter, status: http.HTTPStatus, headers: dict[str, object]):
    writer.write(f"HTTP/1.1 {status.value} {status.phrase}\r\n".encode("utf-8"))
    has_connection = False
    for key, value in headers.items():
        has_connection |= key.lower() == "connection"
        writer.write(f"{key}: {value}\r\n".encode("utf-8"))
    if not has_connection:
        writer.write(b"Connection: keep-alive\r\n")
    writer.write(b"\r\n")


async def _route_stats(cm: "ConnectionManager", writer: asyncio.StreamWriter, request: HTTPRequest):
    if request.command != "GET":
        raise HTTPError(http.HTTPStatus.METHOD_NOT_ALLOWED)
    stream = max(0., float(request.qs.get('stream', ["0"])[0]))
    keys = [x for x in dir(TcpInfo()) if x.startswith("tcpi_")]
    if "cols" in request.qs:
        cols = [y for x in request.qs["cols"] for y in x.split(",")]
        keys = [x for x in cols if x in keys]

    _write_header(writer, http.HTTPStatus.OK, {
        "Content-Type": "text/csv; charset=utf-8" if request.url.path.endswith(".csv") else "text/plain; charset=utf-8",
        "Transfer-Encoding": "chunked"
    })

    chunked_writer = ChunkedStreamWriter(writer)
    _write_csv_line(chunked_writer, "time", "fd", "peer_ip", "peer_port", *keys)
    while True:
        now = datetime.datetime.now(tz=datetime.timezone.utc).isoformat()
        for sock in cm.tracked_sockets:
            try:
                peer_name = sock.getpeername()
                tcp_info = TcpInfo.from_socket(sock)
            except socket.error:
                continue
            _write_csv_line(chunked_writer, now, sock.fileno(), *peer_name, *(getattr(tcp_info, x) for x in keys))

        if stream <= 0:
            chunked_writer.write_final_chunk()
            return

        await writer.drain()
        await asyncio.sleep(stream)


async def _route_firehose_ffxiv(cm: "ConnectionManager", writer: asyncio.StreamWriter, request: HTTPRequest):
    if request.command != "GET":
        raise HTTPError(http.HTTPStatus.METHOD_NOT_ALLOWED)

    # raise HTTPError(http.HTTPStatus.NOT_IMPLEMENTED)
    _write_header(writer, http.HTTPStatus.OK, {
        "Transfer-Encoding": "chunked"
    })
    chunked_writer = ChunkedStreamWriter(writer)
    _write_csv_line(
        chunked_writer,
        "fd", "direction",
        "timestamp", "conn_type",
        "source_actor", "target_actor", "type", "data")

    with cm.ffxiv_packet_observer() as observer:
        while True:
            try:
                sock, direction, timestamp, conn_type, message_header, message_body = await observer.get()
            except ConnectionAbortedError:
                return
            _write_csv_line(
                chunked_writer,
                sock.fileno(), direction,
                timestamp, conn_type,
                message_header.source_actor,
                message_header.target_actor,
                message_header.type_int,
                message_body.hex(" "))
            await writer.drain()


async def _route_http_error(writer: asyncio.StreamWriter, e: HTTPError):
    _write_header(writer, e.status, {
        "Connection": "close" if e.break_keepalive else "keep-alive",
        **e.headers,
    })
    writer.write(e.body)


async def _route(cm: "ConnectionManager", request: HTTPRequest, body: DecodingStreamReader,
                 writer: asyncio.StreamWriter):
    match request.url.path:
        case "/stats" | "/stats.csv":
            await _route_stats(cm, writer, request)
        case "/firehose/ffxiv" | "/firehose/ffxiv.csv":
            await _route_firehose_ffxiv(cm, writer, request)
        case _:
            raise HTTPError(http.HTTPStatus.NOT_FOUND)


async def handle_web_request(conn_id: int, cm: "ConnectionManager",
                             reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    while True:
        try:
            try:
                header = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), _HEADER_TIMEOUT)
            except asyncio.LimitOverrunError:
                raise HTTPError(http.HTTPStatus.BAD_REQUEST, "Header too long", break_keepalive=True)
            except asyncio.TimeoutError:
                raise HTTPError(http.HTTPStatus.REQUEST_TIMEOUT, break_keepalive=True)

            request = HTTPRequest(header)
            logging.info(f"[{conn_id:>4}] {request.command} {request.path}")

            if request.url.netloc or request.url.scheme:
                raise HTTPError(http.HTTPStatus.BAD_REQUEST, break_keepalive=True)

            body = DecodingStreamReader(reader, headers=request.headers, default_empty_body=True)
            await _route(cm, request, body, writer)
            await body.drain()
            await writer.drain()
        except HTTPError as e:
            logging.error(f"[{conn_id:>4}] HTTP {e.status}: {e.body.decode('utf-8')}", exc_info=e.status.value >= 500)
            await _route_http_error(writer, e)
            await writer.drain()
            if e.break_keepalive:
                break
