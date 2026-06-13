import ipaddress
import socket
import time
import typing

from arguments import ArgumentTuple
from utils.interop.linux import TARGET_TYPE
from utils.interop.xivalex import load_definitions, OpcodeDefinition


def create_getaddrinfo_with_timeout(timeout: float):
    until = time.time() + timeout

    def getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
        while True:
            try:
                return socket.getaddrinfo(host, port, family, type, proto, flags)
            except socket.gaierror as e:
                if e.errno not in (socket.EAI_AGAIN, socket.EAI_SYSTEM, socket.EAI_MEMORY, socket.EAI_FAIL):
                    raise
                if time.time() > until:
                    raise
                time.sleep(2)

    return getaddrinfo


def parse_args_targets(targets: list[str], getaddrinfo) -> typing.Iterable[TARGET_TYPE]:
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
            for family, _type, _proto, _canoname, (address, *_) in getaddrinfo(host, 0):
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

        for family, _type, _proto, _canoname, (address, *_) in getaddrinfo(target, 0):
            match family:
                case socket.AF_INET:
                    yield ipaddress.IPv4Network(address, False), ports
                case socket.AF_INET6:
                    yield ipaddress.IPv6Network(address, False), ports


def parse_opcode_definitions(definitions: list[OpcodeDefinition]) -> typing.Iterable[TARGET_TYPE]:
    for definition in definitions:
        for iprange in definition.Server_IpRange:
            yield iprange, [x[0] if x[0] == x[1] else x for x in definition.Server_PortRange]


def get_definitions(args: ArgumentTuple) -> list[OpcodeDefinition]:
    if "off" in args.regions:
        return []

    definitions = load_definitions(args.working_directory, args.update_opcodes, args.opcode_json_path)
    if args.regions and (args.opcode_json_path is None or args.opcode_json_path.strip() == ""):
        definitions = [x for x in definitions if any(r.lower() in x.Name.lower() for r in args.regions)]
    return definitions
