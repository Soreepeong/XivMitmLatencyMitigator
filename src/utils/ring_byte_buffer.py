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

    def compact(self):
        if self._pos == 0:
            pass
        elif self._pos + self._len <= self._buflen:
            self._buffer[:self._len] = self._buffer[self._pos:self._pos + self._len]
            self._pos = 0
        else:
            # https://cplusplus.com/reference/algorithm/rotate/
            f = 0
            m = self._pos
            l = self._buflen
            n = m
            while f != n:
                self._buffer[f], self._buffer[n] = self._buffer[n], self._buffer[f]
                f += 1
                n += 1
                if n == l:
                    n = m
                elif f == m:
                    m = n
            self._pos = 0

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
            self._pos = (self._pos + read) % self._buflen
