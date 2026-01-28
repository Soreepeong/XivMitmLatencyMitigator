import collections
import ipaddress
import itertools
import typing

from utils.consts import NAT64_NETWORK

T = typing.TypeVar("T")

TARGET_ADDRESS_TYPE = typing.Union[
    ipaddress.IPv4Network,
    ipaddress.IPv6Network,
    ipaddress.IPv4Address,
    ipaddress.IPv6Address,
    tuple[ipaddress.IPv4Address, ipaddress.IPv4Address],
    tuple[ipaddress.IPv6Address, ipaddress.IPv6Address],
    None
]
TARGET_PORT_TYPE = typing.Union[int, tuple[int, int], None]
TARGET_TYPE = tuple[
    TARGET_ADDRESS_TYPE,
    collections.abc.Iterable[TARGET_PORT_TYPE]
]


def clamp(v: T, min_: T, max_: T) -> T:
    return max(min_, min(max_, v))


def format_addr_port(addr: ipaddress.IPv4Address | ipaddress.IPv6Address | str, port: int, *_):
    if isinstance(addr, str):
        addr = ipaddress.ip_address(addr)
    if isinstance(addr, ipaddress.IPv4Address):
        return f"{addr}:{port}"
    else:
        return f"[{addr}]:{port}"


def format_addr_port_tuples(*addrs: tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int], sep=", "):
    return sep.join(format_addr_port(*x) for x in addrs)


def generate_nat64_targets(targets: collections.abc.Iterable[TARGET_TYPE]):
    for target, ports in targets:
        if not is_ipv6(target):
            continue
        if isinstance(target, ipaddress.IPv4Address):
            if target.is_unspecified:
                continue
            yield NAT64_NETWORK.network_address + int(target), ports
        elif isinstance(target, ipaddress.IPv4Network):
            if target.is_unspecified:
                continue
            addr = NAT64_NETWORK.network_address + int(target.network_address)
            prefixlen = NAT64_NETWORK.prefixlen + target.prefixlen
            yield ipaddress.IPv6Network(f"{addr}/{prefixlen}"), ports
        elif isinstance(target, tuple):
            yield ((
                (NAT64_NETWORK.network_address + int(target[0]), NAT64_NETWORK.network_address + int(target[1])),
                ports))


def dedup_targets(targets: collections.abc.Iterable[TARGET_TYPE]):
    return [
        (addr, set(itertools.chain.from_iterable(ports for _, ports in v)))
        for addr, v in itertools.groupby(targets, lambda x: x[0])
    ]


def is_ipv6(addr: TARGET_ADDRESS_TYPE):
    return isinstance(addr, (ipaddress.IPv6Address, ipaddress.IPv6Network)) or (
            isinstance(addr, tuple) and len(addr) == 2 and
            isinstance(addr[0], ipaddress.IPv6Address) and isinstance(addr[1], ipaddress.IPv6Address))
