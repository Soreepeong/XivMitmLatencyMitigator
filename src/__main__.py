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
from utils.exceptions import RootRequiredError
from utils.interop.linux import TARGET_TYPE, setup_system_configuration
from utils.interop.oodle import OodleWithBudgetAbiThunks, test_oodle
from utils.interop.xivalex import load_definitions, OpcodeDefinition, MitigationConfig
from utils.interop.zipatch import download_exe


@dataclasses.dataclass
class ArgumentTuple:
    targets: list[str] = dataclasses.field(default_factory=list)
    firewall: str = "none"
    listen: str = "0.0.0.0:0"
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


def parse_args_targets(targets: list[str]) -> typing.Iterable[TARGET_TYPE]:
    for target in targets:
        if ":" in target:
            target, ports = target.split(":", 1)
            ports = [
                tuple(int(y.strip()) for y in x.split("-", 2)) if "-" in x else int(x)
                for x in ports.split(",")
            ]
        else:
            ports = [None]

        target = target.strip()
        if "/" in target:
            host, prefix_length = target.split("/")
            prefix_length = int(prefix_length)
            for address in socket.gethostbyname_ex(host)[2]:
                yield ipaddress.IPv4Network(f"{address}/{prefix_length}", False), ports
        elif re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\s*-\s*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+", target):
            ip1, ip2 = target.split("-", 1)
            yield (ipaddress.IPv4Address(ip1), ipaddress.IPv4Address(ip2)), ports
        else:
            for address in socket.gethostbyname_ex(target)[2]:
                yield ipaddress.IPv4Network(address, False), ports


def parse_opcode_definitions(definitions: list[OpcodeDefinition]) -> typing.Iterable[TARGET_TYPE]:
    for definition in definitions:
        for iprange in definition.Server_IpRange:
            yield iprange, [x[0] if x[0] == x[1] else x for x in definition.Server_PortRange]


def __main__() -> int:
    if sys.version_info < (3, 8):
        print("This script requires at least python 3.8")
        return -1

    logging.basicConfig(level=logging.INFO, force=True,
                        format="%(asctime)s\t%(process)d(main)\t%(levelname)s\t%(message)s",
                        handlers=[
                            logging.StreamHandler(sys.stderr),
                        ])

    parser = argparse.ArgumentParser("XivMitmLatencyMitigator: https://github.com/Soreepeong/XivMitmLatencyMitigator")
    defaults = ArgumentTuple()
    parser.add_argument("-t", "--target", action="append",
                        dest="targets", default=defaults.targets,
                        help="Target host names or IPv4 addresses to take over, optionally with prefix length.")
    parser.add_argument("-l", "--listen", action="store",
                        dest="listen", default=defaults.listen,
                        help="IPv4 address and port to listen to.")
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
    parser.add_argument("-r", "--region", action="append",
                        dest="regions", default=defaults.regions,
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
        targets.append("0.0.0.0/0")

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_address, listen_port, *_ = f"{args.listen}:0".split(":")
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    listener.bind((listen_address, int(listen_port)))
    listen_port = listener.getsockname()[1]

    cleanup_filepath = os.path.join(args.working_directory, ".cleanup.sh")
    if os.path.exists(cleanup_filepath):
        os.system(cleanup_filepath)
        os.remove(cleanup_filepath)

    try:
        with open(cleanup_filepath, "w") as fp:
            fp.write("#!/bin/sh\n")
            fp.writelines(
                setup_system_configuration(targets, args.firewall, args.write_sysctl, listen_address, listen_port))

        os.chmod(cleanup_filepath, 0o777)

        listener.listen()
        logging.info(f"Listening on {listener.getsockname()}...")
        logging.info("Press Ctrl+C to quit.")

        with ConnectionManager(
                listener,
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

    except RootRequiredError:
        logging.error("This program requires root permissions.\n")
        return -1

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
