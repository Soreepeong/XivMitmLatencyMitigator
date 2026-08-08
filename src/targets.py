import ipaddress
import socket
import time
import typing

from arguments import ArgumentTuple
from utils.consts import NAT64_NETWORK
from utils.interop.linux import TARGET_TYPE, TARGET_PORT_TYPE, TARGET_ADDRESS_TYPE
from utils.interop.xivalex import load_definitions, OpcodeDefinition

ROUTED_TARGET_TYPE = tuple[TARGET_ADDRESS_TYPE, list[TARGET_PORT_TYPE], list[str]]


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


def parse_ports(spec: str) -> list[TARGET_PORT_TYPE]:
    ports: list[TARGET_PORT_TYPE] = []
    for item in spec.split(","):
        if "-" in item:
            lo, hi = item.split("-", 1)
            ports.append((int(lo.strip()), int(hi.strip())))
        else:
            ports.append(int(item))
    return ports


def parse_args_targets(routes: list[tuple[str, list[str]]], getaddrinfo) -> typing.Iterable[ROUTED_TARGET_TYPE]:
    for target, interfaces in routes:
        target = target.strip()
        ports: list[TARGET_PORT_TYPE]
        if target.startswith("["):
            if "]:" in target:
                target, port_spec = target[1:].split("]:", 1)
                ports = parse_ports(port_spec)
            elif target.endswith("]"):
                target = target[1:-1]
                ports = [None]
            else:
                raise ValueError(f"\"{target}\" is not a valid target")
        elif ":" in target:
            target, port_spec = target.split(":", 1)
            ports = parse_ports(port_spec)
        else:
            ports = [None]

        if "/" in target:
            host, prefix_length = target.split("/")
            prefix_length = int(prefix_length)
            for family, _type, _proto, _canoname, (address, *_) in getaddrinfo(host, 0):
                match family:
                    case socket.AF_INET:
                        yield ipaddress.IPv4Network(f"{address}/{prefix_length}", False), ports, interfaces
                    case socket.AF_INET6:
                        yield ipaddress.IPv6Network(f"{address}/{prefix_length}", False), ports, interfaces
            continue

        if "-" in target:
            try:
                ip1, ip2 = target.split("-", 1)
                ip1 = ipaddress.ip_address(ip1)
                if isinstance(ip1, ipaddress.IPv4Address):
                    yield (ip1, ipaddress.IPv4Address(ip2)), ports, interfaces
                elif isinstance(ip1, ipaddress.IPv6Address):
                    yield (ip1, ipaddress.IPv6Address(ip2)), ports, interfaces
            except ValueError:
                pass
            else:
                continue

        for family, _type, _proto, _canoname, (address, *_) in getaddrinfo(target, 0):
            match family:
                case socket.AF_INET:
                    yield ipaddress.IPv4Network(address, False), ports, interfaces
                case socket.AF_INET6:
                    yield ipaddress.IPv6Network(address, False), ports, interfaces


def parse_opcode_definitions(definitions: list[OpcodeDefinition]) -> typing.Iterable[TARGET_TYPE]:
    for definition in definitions:
        for iprange in definition.Server_IpRange:
            yield iprange, [x[0] if x[0] == x[1] else x for x in definition.Server_PortRange]


def _address_contains(target: TARGET_ADDRESS_TYPE, ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if target is None:
        return True
    if isinstance(target, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
        return ip.version == target.version and ip in target
    if isinstance(target, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        return ip == target
    if isinstance(target, tuple) and len(target) == 2:
        lo, hi = target
        return ip.version == lo.version and lo <= ip <= hi
    return False


def _port_matches(ports: typing.Iterable[TARGET_PORT_TYPE], port: int) -> bool:
    for spec in ports:
        if spec is None:
            return True
        if isinstance(spec, tuple):
            if spec[0] <= port <= spec[1]:
                return True
        elif spec == port:
            return True
    return False


class UpstreamRouter:
    def __init__(self, routes: typing.Iterable[ROUTED_TARGET_TYPE], default_interfaces: list[str]):
        self._routes = [(addr, list(ports), list(interfaces)) for addr, ports, interfaces in routes]
        self._default = list(default_interfaces)

    def resolve(self, ip: ipaddress.IPv4Address | ipaddress.IPv6Address, port: int) -> list[str]:
        if isinstance(ip, ipaddress.IPv6Address) and ip in NAT64_NETWORK:
            ip = ipaddress.IPv4Address(int(ip) - int(NAT64_NETWORK.network_address))
        for addr, ports, interfaces in self._routes:
            if _address_contains(addr, ip) and _port_matches(ports, port):
                return interfaces
        return self._default


def get_definitions(args: ArgumentTuple) -> list[OpcodeDefinition]:
    if "off" in args.regions:
        if len(args.regions) != 1:
            raise ValueError(f'"{args.regions}" may only contain "off" or anything else')
        return []

    definitions = load_definitions(args.working_directory, args.update_opcodes, args.opcode_json_path)
    if args.regions and (args.opcode_json_path is None or args.opcode_json_path.strip() == ""):
        definitions = [x for x in definitions if any(r.lower() in x.Name.lower() for r in args.regions)]
    return definitions
