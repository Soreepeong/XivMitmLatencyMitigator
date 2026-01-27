import ctypes
import dataclasses
import heapq
import ipaddress
import logging
import selectors
import socket
import time
import typing

from connections.handlers import BaseConnectionHandler, ForwardingConnectionHandler, WebRequestConnectionHandler
from connections.handlers.forwarding_xiv import ForwardingXivConnectionHandler
from utils.exceptions import is_error_nested
from utils.consts import SO_ORIGINAL_DST, IP6T_SO_ORIGINAL_DST
from utils.interop.socket import sockaddr_in, sockaddr_in6
from utils.interop.xivalex import MitigationConfig
from utils.misc import format_addr_port_tuples


class DirectConnectionRejectedError(RuntimeError):
    pass


class ConnectionManager:
    def __init__(self, listeners: list[socket.socket], upstream_interface: str, enable_web: bool,
                 xivalex_mitigation_config: MitigationConfig):
        self._listeners = listeners
        self._selector = selectors.DefaultSelector()
        self._connections = set[BaseConnectionHandler]()
        self._fds = dict[object, BaseConnectionHandler | ConnectionManager]()
        self._conn_id_counter = 0
        self._timers = list[ConnectionManager._TimerEntry]()
        self._closed = True
        self._upstream_interface = upstream_interface
        self._enable_web = enable_web
        self._xivalex = xivalex_mitigation_config

    @property
    def closed(self):
        return self._closed

    @property
    def sockets(self):
        yield from self._listeners
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
                conn = self._fds.get(fd.fileobj, None)
                if conn is None or conn.closed:
                    continue
                try:
                    cb, *args = fd.data
                    cb(*args, ev)
                except BaseException as e:
                    self._error(conn, e)

    def wait_until(self, when: float, owner: BaseConnectionHandler, callback: typing.Callable[[], None]):
        heapq.heappush(self._timers, ConnectionManager._TimerEntry(when, owner, callback))

    def update_statistics(self):
        for c in self._connections:
            if isinstance(c, ForwardingConnectionHandler):
                c.update_statistics()

    def _error(self, instance, e: BaseException):
        assert isinstance(instance, BaseConnectionHandler)
        err: EOFError | StopIteration | None = is_error_nested(e, EOFError, StopIteration)
        if err:
            logging.info(f"[{instance}] ended")
        else:
            err: socket.error | None = is_error_nested(e, socket.error)
            if err:
                logging.error(f"[{instance}] broken; errno {err.errno}: {err.strerror}")
            else:
                logging.error(f"[{instance}] broken", exc_info=True)
        for sock in instance.sockets:
            del self._fds[sock]
        instance.close()
        self._connections.remove(instance)

    def _handle(self, listener: socket.socket, ev: int):
        if not ev & selectors.EVENT_READ:
            return

        self._conn_id_counter += 1

        sock: socket.socket | None = None
        conn: BaseConnectionHandler | None = None
        conn_id = self._conn_id_counter
        down_addr = "<?>"
        log_head = f"[{conn_id:>4}] "
        try:
            sock, down_addr, *_ = listener.accept()
            down_addr = ipaddress.ip_address(down_addr[0]), down_addr[1]
            local_addr = sock.getsockname()
            local_addr = ipaddress.ip_address(local_addr[0]), local_addr[1]
            up_addr = local_addr

            match sock.family:
                case socket.AF_INET:
                    original_dst = sockaddr_in.from_buffer_copy(
                        sock.getsockopt(socket.IPPROTO_IP, SO_ORIGINAL_DST, ctypes.sizeof(sockaddr_in)))
                    up_addr = ipaddress.ip_address(bytes(original_dst.sin_addr)), int(original_dst.sin_port)
                case socket.AF_INET6:
                    try:
                        original_dst = sockaddr_in6.from_buffer_copy(
                            sock.getsockopt(socket.IPPROTO_IPV6, IP6T_SO_ORIGINAL_DST, ctypes.sizeof(sockaddr_in6)))
                        up_addr = ipaddress.ip_address(bytes(original_dst.sin6_addr)), int(original_dst.sin6_port)
                    except FileNotFoundError:
                        print("TODO")  # TODO
                        up_addr = local_addr
                case _:
                    raise AssertionError

            if local_addr != up_addr:
                logging.info(log_head + format_addr_port_tuples(down_addr, local_addr, up_addr, sep=" > "))
                if definitions := [f for f in self._xivalex.definitions if f.is_applicable(*up_addr)]:
                    conn = ForwardingXivConnectionHandler(
                        self._selector, conn_id, sock, up_addr, self._upstream_interface,
                        MitigationConfig(self._xivalex.measure_ping, self._xivalex.extra_delay, definitions))
                else:
                    conn = ForwardingConnectionHandler(
                        self._selector, conn_id, sock, up_addr, self._upstream_interface)
            elif self._enable_web:
                logging.info(log_head + format_addr_port_tuples(down_addr, up_addr, sep=" > "))
                conn = WebRequestConnectionHandler(self, conn_id, sock, down_addr, self._selector)
            else:
                logging.info(f"Rejected " + format_addr_port_tuples(down_addr, up_addr, sep=" > "))
                raise DirectConnectionRejectedError

            self._connections.add(conn)
            for sock in conn.sockets:
                self._fds[sock] = conn
        except DirectConnectionRejectedError:
            pass
        except Exception as e:
            logging.error(f"Failed to accept from {down_addr}", exc_info=e)
        finally:
            if conn is None and sock is not None:
                sock.close()

    def __enter__(self):
        for sock in self._listeners:
            self._selector.register(sock, selectors.EVENT_READ, (self._handle, sock))
            self._fds[sock] = self
        self._closed = False
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._closed = True
        for sock in self._listeners:
            self._selector.unregister(sock)
            del self._fds[sock]
            sock.close()
        self._listeners.clear()

        for conn in self._connections:
            conn.close()
        self._connections.clear()

    @dataclasses.dataclass(order=True)
    class _TimerEntry:
        timeout: float
        instance: BaseConnectionHandler = dataclasses.field(compare=False)
        callback: typing.Callable[[], None] = dataclasses.field(compare=False)
