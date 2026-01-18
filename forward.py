#!/usr/bin/sudo python
import argparse
import collections
import contextlib
import dataclasses
import errno
import ipaddress
import logging.handlers
import os
import selectors
import socket
import struct
import sys
import typing

SO_ORIGINAL_DST = 80
SCRIPT_DIRECTORY = os.path.dirname(os.path.abspath(__file__))
BLOCKING_IO_ERRORS = {socket.EWOULDBLOCK, socket.EAGAIN, errno.EINPROGRESS}


def is_error_nested(e: Exception, error_type: type[Exception]):
    if isinstance(e, error_type):
        return e
    if isinstance(e, ExceptionGroup):
        for e2 in e.exceptions:
            if isinstance(e2, error_type):
                return e2
    return None


@dataclasses.dataclass
class ArgumentTuple:
    targets: list[str] = dataclasses.field(default_factory=list)
    nftables: bool = False
    write_sysctl: bool = True


class RootRequiredError(RuntimeError):
    pass


class ConnectionManager:
    def __init__(self, listener: socket.socket, poller: selectors.BaseSelector, args: ArgumentTuple):
        self._listener = listener
        self._poller = poller
        self._args = args
        self._connections = set[Connection]()

    def error(self, instance, e: Exception):
        assert isinstance(instance, Connection)
        err: EOFError | None = is_error_nested(e, EOFError)
        if err:
            logging.info(f"{instance.log_prefix} ended")
        else:
            err: socket.error | None = is_error_nested(e, socket.error)
            if err:
                logging.error(f"{instance.log_prefix} broken; errno {err.errno}: {err.strerror}")
            else:
                logging.error(f"{instance.log_prefix} broken", exc_info=True)
        instance.close()
        self._connections.remove(instance)

    def _handle(self, ev: int):
        if ev & selectors.EVENT_READ:
            source = "<?>"
            try:
                sock, source = self._listener.accept()
                connection = Connection(self._args, sock, source, self._poller)
            except:
                logging.error(f"Failed to accept from {source}", exc_info=True)
                return
            self._connections.add(connection)

    def __enter__(self):
        self._poller.register(self._listener, selectors.EVENT_READ, (self, self._handle))
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._poller.unregister(self._listener)
        self._listener.close()

        for conn in self._connections:
            conn.close()
        self._connections.clear()


class Connection:
    def __init__(self,
                 args: ArgumentTuple,
                 sock: socket.socket,
                 source: typing.Tuple[str, int],
                 selector: selectors.BaseSelector):
        with contextlib.ExitStack() as self._cleanup:
            def set_closed():
                self._closed = True

            self._cleanup.callback(set_closed)

            self._cleanup.push(sock)
            sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._cleanup.push(sock2)

            self._args = args
            self._closed = False
            self._source = source

            self.log_prefix = f"[{sock.fileno():>6}]"

            srv_port, srv_ip = struct.unpack("!2xH4s8x", sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16))
            self._destination = (socket.inet_ntoa(srv_ip), srv_port)
            logging.info(f"{self.log_prefix} New: " + " <-> ".join(
                f"{x[0]}:{x[1]}" for x in (sock.getpeername(), sock.getsockname(), self._destination)))

            self._down = Connection.Endpoint(self, sock, selector, True, False, self._handle_down)
            self._up = Connection.Endpoint(self, sock2, selector, True, True, self._handle_up)

            try:
                self._up.sock.connect((str(self._destination[0]), self._destination[1]))
            except socket.error as e:
                if e.errno not in BLOCKING_IO_ERRORS:
                    raise

            self._cleanup = self._cleanup.pop_all()

    @property
    def closed(self):
        return self._closed

    def close(self):
        self._cleanup.close()

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
            logging.info(f"{self.log_prefix} Connection established")
            self._down.modify_selector(True, False)
            self._up.modify_selector(True, False, self._handle_up)

    class Endpoint:
        def __init__(self,
                     owner: "Connection",
                     sock: socket.socket,
                     selector: selectors.BaseSelector,
                     event_in: bool,
                     event_out: bool,
                     event_cb: typing.Callable[[int], None]):
            self._owner = owner
            self.sock = sock
            self.bufs = collections.deque[memoryview]()
            self._poller = selector
            self._event_in = event_in
            self._event_out = event_out
            self._event_cb = event_cb
            self._read_err = self._write_err = None

            sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
            sock.setsockopt(socket.SOL_TCP, socket.TCP_QUICKACK, 1)
            sock.setblocking(False)
            selector.register(sock, (
                    0
                    | (selectors.EVENT_READ if event_in else 0)
                    | (selectors.EVENT_WRITE if event_out else 0)
            ), (owner, event_cb))
            owner._cleanup.callback(selector.unregister, sock)

        def fileno(self):
            return self.sock.fileno()

        def handle(self, ev: int, target: "Connection.Endpoint"):
            if ev & selectors.EVENT_READ:
                try:
                    for _ in range(4):
                        data = self.sock.recv(4096)
                        if data:
                            self.bufs.append(memoryview(data))
                        else:
                            self._read_err = EOFError()
                            break
                except socket.error as e:
                    if e.errno not in BLOCKING_IO_ERRORS:
                        self._read_err = e
                self._forward_to(target)

            if ev & selectors.EVENT_WRITE:
                if not self.bufs:
                    target.modify_selector(event_out=False)
                    if self._read_err:
                        target.sock.shutdown(socket.SHUT_WR)

                target._forward_to(self)

            if self._read_err and target._read_err and (not self.bufs or self._write_err) and (not target.bufs or target._write_err):
                raise ExceptionGroup("Both socket closed", (self._read_err, target._read_err))

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
                self._poller.modify(self.sock, eventmask, (self._owner, self._event_cb))

        def _forward_to(self, target: "Connection.Endpoint"):
            while self.bufs:
                buf = self.bufs.popleft()
                try:
                    while buf:
                        buf = buf[target.sock.send(buf):]
                except socket.error as e:
                    if e.errno not in BLOCKING_IO_ERRORS:
                        self._write_err = e
                        break
                    self.bufs.appendleft(buf)
                    self.modify_selector(event_in=False)
                    target.modify_selector(event_out=True)
                    return

            self.modify_selector(event_in=not self._read_err)


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
    parser.add_argument("-n", "--nftables", action="store_true", dest="nftables", default=defaults.nftables)
    parser.add_argument("--no-sysctl", action="store_false", dest="write_sysctl", default=defaults.write_sysctl)

    args: ArgumentTuple | argparse.Namespace = parser.parse_args()

    if len(args.targets) == 0:
        logging.error("No targets specified")
        return -1

    logging.info(f"Write sysctl values: {'yes' if args.write_sysctl else 'no'}")

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("0.0.0.0", 0))
    port = listener.getsockname()[1]

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
                rule = f"ip nat PREROUTING meta l4proto tcp ip daddr {target} dnat 127.0.0.1:{port}"
                fw_setup_cmds.append(f"nft -a -e add rule {rule}")
            else:
                rule = f"-t nat -p tcp -d {target} -j REDIRECT --to {port}"
                fw_setup_cmds.append(f"iptables -I PREROUTING {rule}")
                removal_cmds.append(f"iptables -D PREROUTING {rule}")

        if args.nftables:
            fw_setup_cmds.append(f"nft -a -e add rule ip filter INPUT tcp dport {port} accept")
        else:
            fw_setup_cmds.append(f"iptables -I INPUT -t filter -p tcp --dport {port} -j ACCEPT")
            removal_cmds.append(f"iptables -D INPUT -t filter -p tcp --dport {port} -j ACCEPT")

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

        with selectors.DefaultSelector() as selector, ConnectionManager(listener, selector, args) as manager:
            while True:
                for fd, ev in selector.select():
                    instance, handler = fd.data
                    try:
                        handler(ev)
                    except Exception as e:
                        manager.error(instance, e)

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
