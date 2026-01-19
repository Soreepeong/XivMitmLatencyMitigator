import dataclasses
import heapq
import ipaddress
import logging
import selectors
import socket
import struct
import time
import typing

from connections.handlers import BaseConnectionHandler, ForwardingConnectionHandler, WebRequestConnectionHandler
from utils.exceptions import is_error_nested
from utils.consts import SO_ORIGINAL_DST
from utils.interop.xivalex import OpcodeDefinition, MitigationConfig


class ConnectionManager:
    def __init__(self, listener: socket.socket, upstream_interface: str, enable_web: bool,
                 xivalex_mitigation_config: MitigationConfig):
        self._listener = listener
        self._selector = selectors.DefaultSelector()
        self._connections = set[BaseConnectionHandler]()
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
            sock = None
            try:
                sock, down_addr = self._listener.accept()
                self._conn_id_counter += 1
                conn_id = self._conn_id_counter
                srv_port, srv_ip = struct.unpack("!2xH4s8x", sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16))
                srv_ip = socket.inet_ntoa(srv_ip)
                local_addr = sock.getsockname()
                up_addr = srv_ip, srv_port
                log_head = f"[{conn_id:>4}] "

                if local_addr != up_addr:
                    logging.info(log_head + " > ".join(f"{x[0]}:{x[1]}" for x in (down_addr, local_addr, up_addr)))
                    xivalex = MitigationConfig(
                        self._xivalex.measure_ping,
                        self._xivalex.extra_delay,
                        [
                            f for f in self._xivalex.definitions
                            if (
                                any(ipaddress.IPv4Address(srv_ip) in x for x in f.Server_IpRange) and
                                any(x[0] <= srv_port <= x[1] for x in f.Server_PortRange))
                        ]
                    )
                    self._connections.add(ForwardingConnectionHandler(
                        conn_id, sock, down_addr, up_addr, self._selector, self._upstream_interface,
                        xivalex if xivalex.definitions else None
                    ))
                elif self._enable_web:
                    logging.info(log_head + " > ".join(f"{x[0]}:{x[1]}" for x in (down_addr, up_addr)))
                    self._connections.add(WebRequestConnectionHandler(self, conn_id, sock, down_addr, self._selector))
                else:
                    logging.info(f"{log_head}Rejected " + " > ".join(f"{x[0]}:{x[1]}" for x in (down_addr, up_addr)))
                    sock.close()
            except:
                logging.error(f"Failed to accept from {down_addr}", exc_info=True)
                try:
                    sock.close()
                except:
                    pass
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
        instance: BaseConnectionHandler = dataclasses.field(compare=False)
        callback: typing.Callable[[], None] = dataclasses.field(compare=False)
