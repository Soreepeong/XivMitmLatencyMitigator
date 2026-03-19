import asyncio
import csv
import datetime
import http.server
import io
import logging
import socket
import typing
import urllib.parse

from structs.tcp_info import TcpInfo

if typing.TYPE_CHECKING:
    from connections.manager import ConnectionManager

_MAX_HEADER_LENGTH = 32768


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


def _writecsv(writer: asyncio.StreamWriter, *args):
    parts = []
    for arg in args:
        s = str(arg)
        if '"' in s or ',' in s:
            s = '"' + s.replace('"', '""') + '"'
        parts.append(s)
    writer.write((",".join(parts) + "\r\n").encode("utf-8"))


async def _route_stats(cm: "ConnectionManager", writer: asyncio.StreamWriter, url: urllib.parse.ParseResult, qs: dict):
    stream = max(0., float(qs.get('stream', ["0"])[0]))
    keys = [x for x in dir(TcpInfo()) if x.startswith("tcpi_")]
    if "cols" in qs:
        cols = [y for x in qs["cols"] for y in x.split(",")]
        keys = [x for x in cols if x in keys]

    writer.write(b"HTTP/1.1 200 OK\r\n")
    writer.write(b"Connection: Close\r\n")
    if url.path.endswith(".csv"):
        writer.write(b"Content-Type: text/csv; charset=utf-8\r\n")
    else:
        writer.write(b"Content-Type: text/plain; charset=utf-8\r\n")
    writer.write(b"\r\n")
    _writecsv(writer, "time", "fd", "peer_ip", "peer_port", *keys)
    await writer.drain()

    while True:
        now = datetime.datetime.now(tz=datetime.timezone.utc).isoformat()
        for sock in cm.tracked_sockets:
            try:
                peer_name = sock.getpeername()
                tcp_info = TcpInfo.from_socket(sock)
            except socket.error:
                continue
            _writecsv(writer, now, sock.fileno(), *peer_name, *(getattr(tcp_info, x) for x in keys))

        if stream <= 0:
            break

        await writer.drain()
        await asyncio.sleep(stream)


async def _route_400(writer: asyncio.StreamWriter):
    writer.write(b"HTTP/1.1 400 Bad Request\r\n")
    writer.write(b"Connection: Close\r\n")
    writer.write(b"Content-Type: text/plain; charset=utf-8\r\n")
    writer.write(b"\r\n")
    writer.write(b"Bad Request\r\n")


async def _route_404(writer: asyncio.StreamWriter):
    writer.write(b"HTTP/1.1 404 Not Found\r\n")
    writer.write(b"Connection: Close\r\n")
    writer.write(b"Content-Type: text/plain; charset=utf-8\r\n")
    writer.write(b"\r\n")
    writer.write(b"Not Found\r\n")


async def handle_web_request(conn_id: int, cm: "ConnectionManager",
                             reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    data = bytearray()
    while b"\r\n\r\n" not in data:
        chunk = await reader.read(8192)
        if not chunk or len(data) + len(chunk) > _MAX_HEADER_LENGTH:
            return await _route_400(writer)
        data.extend(chunk)

    header_end = data.index(b"\r\n\r\n")
    request = HTTPRequest(data[:header_end])
    url = urllib.parse.urlparse(request.path)
    qs = urllib.parse.parse_qs(url.query)
    logging.info(f"[{conn_id:>4}] {request.command} {request.path}")

    if url.path in ("/stats", "/stats.csv"):
        await _route_stats(cm, writer, url, qs)
    else:
        await _route_404(writer)
    return await writer.drain()
