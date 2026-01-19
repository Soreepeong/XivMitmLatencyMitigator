import socket
import typing


class BaseConnectionHandler:
    def close(self):
        raise NotImplementedError

    @property
    def closed(self) -> bool:
        raise NotImplementedError

    @property
    def sockets(self) -> typing.Iterable[socket.socket]:
        raise NotImplementedError
