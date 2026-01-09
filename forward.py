#!/usr/bin/sudo python
import argparse
import collections
import dataclasses
import logging.handlers
import os
import random
import select
import socket
import struct
import sys
import typing

SO_ORIGINAL_DST = 80
SCRIPT_DIRECTORY = os.path.dirname(os.path.abspath(__file__))

ArgumentTuple = collections.namedtuple(
    "ArgumentTuple",
    ("nftables", "write_sysctl")
)


class InvalidDataException(ValueError):
    pass


class RootRequiredError(RuntimeError):
    pass


# endregion

# region Implementation


@dataclasses.dataclass
class SocketSet:
    source: socket.socket
    target: socket.socket
    log_prefix: str
    done: bool = False
    outgoing: typing.Optional[bytearray] = dataclasses.field(default_factory=bytearray)


class Connection:
    def __init__(self, sock: socket.socket, source: typing.Tuple[str, int], args: ArgumentTuple):
        self.args = args

        self.source = source
        self.downstream = sock
        self.downstream.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
        self.downstream.setsockopt(socket.SOL_TCP, socket.TCP_QUICKACK, 1)
        self.downstream.setblocking(False)

        self.screen_prefix = f"[{os.getpid():>6}]"
        srv_port, srv_ip = struct.unpack("!2xH4s8x", self.downstream.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16))
        self.destination = (socket.inet_ntoa(srv_ip), srv_port)

        self.upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.upstream.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
        self.upstream.setsockopt(socket.SOL_TCP, socket.TCP_QUICKACK, 1)
        self.upstream.setblocking(False)

        logging.info(f"New {self.downstream.getsockname()} {self.downstream.getpeername()} {self.destination}")

    def run(self):
        try:
            with self.downstream, self.upstream:
                self.upstream.settimeout(3)
                self.upstream.connect((str(self.destination[0]), self.destination[1]))
                self.upstream.settimeout(None)

                check_targets = (
                    SocketSet(self.downstream, self.upstream, "D->U"),
                    SocketSet(self.upstream, self.downstream, "U->D"),
                )
                while any(not v.done for v in check_targets):
                    rlist, wlist, _ = select.select(
                        [v.source for v in check_targets if not v.done],
                        [v.target for v in check_targets if v.outgoing],
                        [])

                    for pair in check_targets:
                        if pair.source in rlist:
                            try:
                                data = pair.source.recv(65536)
                                if not data:
                                    pair.done = True
                                else:
                                    pair.outgoing.extend(data)
                            except socket.error as e:
                                if e.errno not in (socket.EWOULDBLOCK, socket.EAGAIN):
                                    raise
                           
                        if pair.outgoing:
                            try:
                                del pair.outgoing[:pair.target.send(pair.outgoing)]
                            except socket.error as e:
                                if e.errno not in (socket.EWOULDBLOCK, socket.EAGAIN):
                                    raise
                        elif pair.done:
                            try:
                                pair.target.shutdown(socket.SHUT_WR)
                            except OSError:
                                pass
            logging.info("Closed")
            return 0
        except Exception as e:
            logging.info(f"Closed, exception occurred: {type(e)} {e}", exc_info=True)
            return -1

# endregion


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
    parser.add_argument("-n", "--nftables", action="store_true", dest="nftables", default=False)
    parser.add_argument("--no-sysctl", action="store_false", dest="write_sysctl", default=True)

    args: typing.Union[ArgumentTuple, argparse.Namespace] = parser.parse_args()

    logging.info(f"Write sysctl values: {'yes' if args.write_sysctl else 'no'}")

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if hasattr(socket, "TCP_NODELAY"):
        listener.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
    if hasattr(socket, "TCP_QUICKACK"):
        listener.setsockopt(socket.SOL_TCP, socket.TCP_QUICKACK, 1)
    while True:
        port = random.randint(10000, 65535)
        try:
            listener.bind(("0.0.0.0", port))
        except OSError:
            continue
        break

    err = 0
    is_child = False
    cleanup_filepath = os.path.join(SCRIPT_DIRECTORY, ".cleanup.sh")
    if os.path.exists(cleanup_filepath):
        os.system(cleanup_filepath)

    try:
        fw_setup_cmds = []
        removal_cmds = []
        for i, iprange in enumerate(["204.2.29.0/24"]):
            if args.nftables:
                rule = f"ip nat PREROUTING meta l4proto tcp ip daddr {iprange} dnat 127.0.0.1:{port}"
                fw_setup_cmds.append(f"nft rule {rule}")
                removal_cmds.append(f"nft delete rule {rule}")
            else:
                rule = f"-t nat -p tcp -d {iprange} -j REDIRECT --to {port}"
                fw_setup_cmds.append(f"iptables -I PREROUTING {rule}")
                removal_cmds.append(f"iptables -D PREROUTING {rule}")

        if args.nftables:
            fw_setup_cmds.append(f"nft rule ip filter INPUT tcp dport {port} accept")
            removal_cmds.append(f"nft delete rule ip filter INPUT tcp dport {port} accept")
        else:
            fw_setup_cmds.append(f"iptables -I INPUT -t filter -p tcp --dport {port} -j ACCEPT")
            removal_cmds.append(f"iptables -D INPUT -t filter -p tcp --dport {port} -j ACCEPT")

        with open(cleanup_filepath, "w") as fp:
            fp.write("#!/bin/sh\n")
            fp.writelines(removal_cmds)

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

        while True:
            sock, source = listener.accept()

            child_pid = os.fork()
            if child_pid == 0:
                is_child = True
                listener.close()

                return Connection(sock, source, args).run()

            sock.close()

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
            os.remove(cleanup_filepath)
            if err:
                logging.error("One or more error have occurred during cleanup.")
                err = -1
            else:
                logging.info("Cleanup complete.")
    return err


if __name__ == "__main__":
    exit(__main__())