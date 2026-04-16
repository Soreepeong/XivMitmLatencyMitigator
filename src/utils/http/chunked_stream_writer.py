import asyncio


class ChunkedStreamWriter:
    def __init__(self, writer: asyncio.StreamWriter):
        self._writer = writer

    def write(self, data: bytes) -> None:
        if not data:
            return

        chunk_header = f"{len(data):x}\r\n"
        self._writer.write(chunk_header.encode())
        self._writer.write(data)
        self._writer.write(b"\r\n")

    def write_final_chunk(self) -> None:
        self._writer.write(b"0\r\n\r\n")
