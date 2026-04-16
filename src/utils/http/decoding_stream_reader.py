import asyncio
import email
import zlib

_SUPPORTED_TRANSFER_ENCODINGS = {"chunked", "identity"}
_SUPPORTED_CONTENT_ENCODINGS = {"gzip", "deflate", "identity", "br"}


class DecodingStreamReader:
    def __init__(
            self,
            reader: asyncio.StreamReader,
            headers: email.message.Message,
            default_empty_body: bool = False
    ):
        transfer_encoding = headers.get("transfer-encoding", None)
        if isinstance(transfer_encoding, str):
            transfer_encoding = [x.strip().lower() for x in transfer_encoding.split(',')]
            transfer_encoding = [x for x in transfer_encoding if x]
        if transfer_encoding is None:
            transfer_encoding = []

        content_encoding = headers.get("content-encoding", None)
        if isinstance(content_encoding, str):
            content_encoding = [x.strip().lower() for x in content_encoding.split(',')]
            content_encoding = [x for x in content_encoding if x]
        elif content_encoding is None:
            content_encoding = []

        content_length = headers.get("content-length", None)
        if isinstance(content_length, str):
            content_length = int(content_length, 10)

        if not transfer_encoding and not content_encoding and content_length is None and default_empty_body:
            content_length = 0

        if unsupported_te := [te for te in transfer_encoding if te not in _SUPPORTED_TRANSFER_ENCODINGS]:
            raise ValueError(f"Unsupported Transfer-Encoding: {', '.join(unsupported_te)}")
        non_identity_te = [te for te in transfer_encoding if te != "identity"]
        if len(non_identity_te) > 1:
            raise ValueError(
                f"At most one non-identity Transfer-Encoding is supported, got: {', '.join(non_identity_te)}")

        if unsupported_ce := [ce for ce in content_encoding if ce not in _SUPPORTED_CONTENT_ENCODINGS]:
            raise ValueError(f"Unsupported Content-Encoding: {', '.join(unsupported_ce)}")
        non_identity_ce = [ce for ce in content_encoding if ce != "identity"]
        if len(non_identity_ce) > 1:
            raise ValueError(
                f"At most one non-identity Content-Encoding is supported, got: {', '.join(non_identity_ce)}")

        self._reader = reader
        self._is_chunked = "chunked" in transfer_encoding
        self._remaining = content_length  # None means read until connection close
        self._buf = b""
        self._eof = False
        self._decompressor = self._make_decompressor(non_identity_ce[0] if non_identity_ce else None)

    @staticmethod
    def _make_decompressor(encoding: str | None = None):
        match encoding:
            case "gzip":
                return zlib.decompressobj(wbits=31)
            case "deflate":
                return zlib.decompressobj()
            case "br":
                try:
                    import brotli
                    return brotli.Decompressor()
                except ImportError:
                    raise ValueError("Content-Encoding 'br' requires the 'brotli' package")
            case "" | None:
                return None
            case _:
                raise ValueError(f"Unsupported Content-Encoding: {encoding}")

    async def _fetch(self) -> None:
        if self._eof:
            return
        if self._is_chunked:
            raw = await self._read_one_chunk()
        elif self._remaining is not None:
            if self._remaining == 0:
                self._eof = True
                return
            raw = await self._reader.read(min(8192, self._remaining))
            self._remaining -= len(raw)
            if self._remaining == 0:
                self._eof = True
        else:
            raw = await self._reader.read(8192)

        if not raw:
            self._eof = True
            return

        if self._decompressor is not None:
            raw = self._decompressor.decompress(raw)

        self._buf += raw

    async def _read_one_chunk(self) -> bytes:
        line = await self._reader.readuntil(b"\r\n")
        line = line.strip()
        if b";" in line:
            # ignore chunk extension if any
            line = line.split(b";")[0]

        try:
            chunk_size = int(line, 16)
        except ValueError:
            self._eof = True
            raise ValueError(f"Invalid chunk size \"{line}\"")

        if chunk_size == 0:
            self._eof = True
            if await self._reader.read(2) != b'\r\n':
                raise ValueError("Invalid final chunk terminator that is not \\r\\n")
            return b""

        data = await self._reader.readexactly(chunk_size)
        if await self._reader.read(2) != b'\r\n':
            self._eof = True
            raise ValueError("Invalid chunk terminator that is not \\r\\n")

        return data

    def at_eof(self) -> bool:
        return self._eof and not self._buf

    async def drain(self, n: int = -1) -> None:
        if n == -1:
            while not self._eof:
                self._buf = None
                await self._fetch()

            self._buf = None
            return

        while not self._buf and not self._eof:
            await self._fetch()
            if len(self._buf) <= n:
                self._buf = b""
                n -= len(self._buf)
            else:
                self._buf = self._buf[n:]

    async def read(self, n: int = -1) -> bytes:
        if n == -1:
            while not self._eof:
                await self._fetch()
            data, self._buf = self._buf, b""
            return data
        while not self._buf and not self._eof:
            await self._fetch()
        n = min(len(self._buf), n)
        data, self._buf = self._buf[:n], self._buf[n:]
        return data

    async def readexactly(self, n: int) -> bytes:
        while len(self._buf) < n and not self._eof:
            await self._fetch()
        if len(self._buf) < n:
            raise asyncio.IncompleteReadError(self._buf, n)
        data, self._buf = self._buf[:n], self._buf[n:]
        return data

    async def readline(self) -> bytes:
        while b"\n" not in self._buf and not self._eof:
            await self._fetch()
        idx = self._buf.find(b"\n")
        if idx == -1:
            data, self._buf = self._buf, b""
            return data
        data, self._buf = self._buf[:idx + 1], self._buf[idx + 1:]
        return data
