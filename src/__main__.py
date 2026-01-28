#!/usr/bin/sudo python
import argparse
import dataclasses
import ipaddress
import logging.handlers
import os
import re
import socket
import sys
import typing

from connections.manager import ConnectionManager
from utils.consts import DUMMY_NET_NAME
from utils.exceptions import SubprocessFailedError
from utils.interop.linux import TARGET_TYPE, setup_system_configuration
from utils.interop.oodle import OodleWithBudgetAbiThunks, test_oodle
from utils.interop.xivalex import load_definitions, OpcodeDefinition, MitigationConfig
from utils.interop.zipatch import download_exe
from utils.misc import format_addr_port, dedup_targets, generate_nat64_targets


@dataclasses.dataclass
class ArgumentTuple:
    targets: list[str] = dataclasses.field(default_factory=list)
    firewall: str = "none"
    listen: list[str] = dataclasses.field(default_factory=list)
    write_sysctl: bool = False
    enable_web_statistics: bool = False
    regions: list[str] = dataclasses.field(default_factory=list)
    extra_delay: float = 0.075
    measure_ping: bool = False
    update_opcodes: bool = False
    opcode_json_path: str | None = None
    ffxiv_exe_urls: list[str] = dataclasses.field(default_factory=list)
    upstream_interface: str | None = None
    working_directory: str | None = None
    dummy_addr4: str = "215.14.52.234"  # random IPv4 address under US DoD address space
    dummy_addr6: str = "fd83:191b:5ab5:145c:15fe:a835:d640:69fe"  # random local IPv6 address
    nftables_meta_mark: int = 0xFF14EE03


def parse_args_targets(targets: list[str]) -> typing.Iterable[TARGET_TYPE]:
    for target in targets:
        target = target.strip()
        if target.startswith("["):
            if "]:" in target:
                target, ports = target[1:].split("]:", 1)
                ports = [
                    tuple(int(y.strip()) for y in x.split("-", 2)) if "-" in x else int(x)
                    for x in ports.split(",")
                ]
            elif target.endswith("]"):
                target = target[1:-1]
                ports = [None]
            else:
                raise ValueError(f"\"{target}\" is not a valid target")
        elif ":" in target:
            target, ports = target.split(":", 1)
            ports = [
                tuple(int(y.strip()) for y in x.split("-", 2)) if "-" in x else int(x)
                for x in ports.split(",")
            ]
        else:
            ports = [None]

        if "/" in target:
            host, prefix_length = target.split("/")
            prefix_length = int(prefix_length)
            for family, _type, _proto, _canoname, (address, *_) in socket.getaddrinfo(host, 0):
                match family:
                    case socket.AF_INET:
                        yield ipaddress.IPv4Network(f"{address}/{prefix_length}", False), ports
                    case socket.AF_INET6:
                        yield ipaddress.IPv6Network(f"{address}/{prefix_length}", False), ports
            continue

        if "-" in target:
            try:
                ip1, ip2 = target.split("-", 1)
                ip1 = ipaddress.ip_address(ip1)
                if isinstance(ip1, ipaddress.IPv4Address):
                    yield (ip1, ipaddress.IPv4Address(ip2)), ports
                elif isinstance(ip1, ipaddress.IPv6Address):
                    yield (ip1, ipaddress.IPv6Address(ip2)), ports
            except ValueError:
                pass
            else:
                continue

        for family, _type, _proto, _canoname, (address, *_) in socket.getaddrinfo(target, 0):
            match family:
                case socket.AF_INET:
                    yield ipaddress.IPv4Network(address, False), ports
                case socket.AF_INET6:
                    yield ipaddress.IPv6Network(address, False), ports


def parse_opcode_definitions(definitions: list[OpcodeDefinition]) -> typing.Iterable[TARGET_TYPE]:
    for definition in definitions:
        for iprange in definition.Server_IpRange:
            yield iprange, [x[0] if x[0] == x[1] else x for x in definition.Server_PortRange]


def listener_from_address(address: str):
    address = re.sub(r'\s', '', address)
    if not address.startswith('['):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        if ':' in address:
            address, port = address.split(":", 1)
            sock.bind((address, int(port)))
        else:
            sock.bind((address, 0))
    else:
        address = address[1:]
        address, port = address.split(']', 1)
        if not port:
            port = 0
        elif port.startswith(':'):
            port = int(port[1:], 10)
        else:
            raise ValueError("invalid ipv6 with port notation")
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sock.bind((address, port))
    return sock


def __main__() -> int:
    logging.basicConfig(level=logging.INFO, force=True,
                        format="%(asctime)s\t%(process)d(main)\t%(levelname)s\t%(message)s",
                        handlers=[
                            logging.StreamHandler(sys.stderr),
                        ])

    parser = argparse.ArgumentParser("XivMitmLatencyMitigator",
                                     description="https://github.com/Soreepeong/XivMitmLatencyMitigator")
    defaults = ArgumentTuple()
    parser.add_argument("-t", "--target", action="append",
                        dest="targets", default=defaults.targets,
                        help="Target host names or IPv4 addresses to take over, optionally with prefix length.")
    parser.add_argument("-l", "--listen", action="append",
                        dest="listen", default=defaults.listen,
                        help="IP address and port to listen to.")
    parser.add_argument("-f", "--firewall", action="store",
                        dest="firewall", default=defaults.firewall, choices=["none", "iptables", "nftables"],
                        help="Firewall to use to enable NAT towards this application.")
    parser.add_argument("-i", "--interface", action="store",
                        dest="upstream_interface", default=defaults.upstream_interface,
                        help="Specify which interface to use for upstream connections.")
    parser.add_argument("-d", "--directory", action="store",
                        dest="working_directory", default=defaults.working_directory,
                        help="Directory to look for and store supporting files.")
    parser.add_argument("-s", "--write-sysctl", action="store_true",
                        dest="write_sysctl", default=defaults.write_sysctl,
                        help="Automatically issue sysctl commands to enable IPv4 forwarding.")
    parser.add_argument("-w", "--web-statistics", action="store_true",
                        dest="enable_web_statistics", default=defaults.enable_web_statistics,
                        help="Enable web interface for displaying statistics.")
    parser.add_argument("-r", "--region", action="append", type=lambda x: x.lower(),
                        dest="regions", default=defaults.regions, choices=["jp", "cn", "kr", "tw", "off"],
                        help="Filters connections by regions. Does nothing if -j is specified.")
    parser.add_argument("-e", "--extra-delay", action="store",
                        dest="extra_delay", default=defaults.extra_delay, type=float,
                        help="Time taken for the server to process the action, in seconds.")
    parser.add_argument("-m", "--measure-ping", action="store_true",
                        dest="measure_ping", default=defaults.measure_ping,
                        help="Use measured latency from sockets to server and client to adjust extra delay.")
    parser.add_argument("-u", "--update-opcodes", action="store_true",
                        dest="update_opcodes", default=defaults.update_opcodes,
                        help="Download new opcodes again; do not use cached opcodes file.")
    parser.add_argument("-j", "--json-path", action="store",
                        dest="opcode_json_path", default=defaults.opcode_json_path,
                        help="Read opcode definition JSON file from the given path.")
    parser.add_argument("-x", "--exe", action="append",
                        dest="ffxiv_exe_urls", default=defaults.ffxiv_exe_urls,
                        help="Download ffxiv.exe and/or ffxiv_dx11.exe from specified URL (exe or patch file.)")
    parser.add_argument("--dummy-addr4", action="store",
                        dest="dummy_addr4", default=defaults.dummy_addr4,
                        help="Dummy IPv4 address for redirecting to this application's socket.")
    parser.add_argument("--dummy-addr6", action="store",
                        dest="dummy_addr6", default=defaults.dummy_addr6,
                        help="Dummy IPv6 address for redirecting to this application's socket.")
    parser.add_argument("--nftables-meta-mark", action="store", type=int,
                        dest="nftables_meta_mark", default=defaults.nftables_meta_mark,
                        help="Meta mark to set for packets that should be accepted. Useful if there are other tables utilizing drop policy.")

    args = ArgumentTuple(**vars(parser.parse_args()))

    if args.working_directory is None:
        args.working_directory = os.getcwd()

    if sys.platform != 'linux':
        logging.error("This script only runs on Linux.")
        return -1

    if args.extra_delay < 0:
        logging.warning("Extra delay cannot be a negative number.")
        return -1

    for url in args.ffxiv_exe_urls:
        url = url.strip()
        if url:
            download_exe(url)

    if "off" in args.regions:
        definitions = list[OpcodeDefinition]()
    else:
        try:
            OodleWithBudgetAbiThunks.init_module(args.working_directory)
            test_oodle()
        except Exception as e:
            logging.error(str(e))
            return -1

        definitions = load_definitions(args.working_directory, args.update_opcodes, args.opcode_json_path)
        if args.regions and (args.opcode_json_path is None or args.opcode_json_path.strip() == ""):
            definitions = [x for x in definitions if any(r.lower() in x.Name.lower() for r in args.regions)]

    targets = [
        *parse_args_targets(args.targets),
        *parse_opcode_definitions(definitions),
    ]

    if len(targets) == 0:
        targets.append(ipaddress.IPv4Address("0.0.0.0/0"))
        targets.append(ipaddress.IPv6Address("::0/0"))

    cleanup_filepath = os.path.join(args.working_directory, ".cleanup.sh")
    if os.path.exists(cleanup_filepath):
        os.system(cleanup_filepath)
        os.remove(cleanup_filepath)

    try:
        with open(cleanup_filepath, "w", opener=lambda path, flags: os.open(path, flags, 0o755)) as fp:
            fp.write("#!/bin/sh\n")

            # https://serverfault.com/questions/975558/nftables-ip6-route-to-localhost-ipv6-nat-to-loopback
            fp.write(f"ip link delete {DUMMY_NET_NAME}\n")
            for cmd in (
                    f"ip link add {DUMMY_NET_NAME} type dummy",
                    f"ip link set {DUMMY_NET_NAME} up",
                    f"ip addr add {args.dummy_addr4} dev {DUMMY_NET_NAME}",
                    f"ip addr add {args.dummy_addr6} dev {DUMMY_NET_NAME}",
            ):
                SubprocessFailedError.raise_if_nonzero(os.system(cmd))

            listeners = [
                listener_from_address(f"{args.dummy_addr4}:0"),
                listener_from_address(f"[{args.dummy_addr6}]:0"),
                *(listener_from_address(x) for x in args.listen)
            ]

            if any(x.family == socket.AF_INET6 for x in listeners):
                targets.extend(generate_nat64_targets(targets))
            targets = dedup_targets(targets)

            fp.writelines(setup_system_configuration(
                targets, args.firewall, args.nftables_meta_mark, args.write_sysctl, listeners))

        for listener in listeners:
            listener.listen()
            logging.info(f"Listening on: {format_addr_port(*listener.getsockname())}")
        logging.info("Press Ctrl+C to quit.")

        with ConnectionManager(
                listeners,
                args.upstream_interface,
                args.enable_web_statistics,
                MitigationConfig(
                    args.measure_ping,
                    args.extra_delay,
                    definitions,
                ),
        ) as manager:
            manager.serve_forever()
        return 0

    except SubprocessFailedError as e:
        return e.code

    except KeyboardInterrupt:
        return 0

    finally:
        logging.info("Cleaning up...")
        if os.path.exists(cleanup_filepath):
            os.system(cleanup_filepath)
            os.remove(cleanup_filepath)
        logging.info("Cleanup complete.")


if __name__ == "__main__":
    exit(__main__())
