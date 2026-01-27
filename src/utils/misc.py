import ipaddress
import typing

T = typing.TypeVar("T")


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
