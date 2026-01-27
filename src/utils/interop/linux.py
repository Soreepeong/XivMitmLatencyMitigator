import ipaddress
import json
import os
import shlex
import socket
import subprocess
import typing

from utils.consts import SYSCTL_VARS
from utils.exceptions import RootRequiredError

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
    list[TARGET_PORT_TYPE]
]


class NftExprGenerators:
    @staticmethod
    def l4proto(proto: str):
        yield {"match": {"op": "==", "left": {"meta": {"key": "l4proto"}}, "right": proto}}

    @staticmethod
    def ip_daddr(*ips: TARGET_ADDRESS_TYPE):
        exprs = []
        ipv4 = ipv6 = False
        for ip in ips:
            if ip is None:
                return
            elif isinstance(ip, tuple) and len(ip) == 2:
                ipv4 |= isinstance(ip[0], ipaddress.IPv4Address)
                ipv6 |= isinstance(ip[0], ipaddress.IPv6Address)
                exprs.append({"range": [str(x) for x in ip]})
            elif isinstance(ip, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
                ipv4 |= isinstance(ip, ipaddress.IPv4Network)
                ipv6 |= isinstance(ip, ipaddress.IPv6Network)
                if ip.is_unspecified or ip.prefixlen == 0:
                    return
                elif ip.prefixlen == ip.max_prefixlen:
                    exprs.append(ip.network_address.exploded)
                else:
                    exprs.append({"prefix": {"addr": ip.network_address.exploded, "len": ip.prefixlen}})
            elif isinstance(ip, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
                ipv4 |= isinstance(ip, ipaddress.IPv4Address)
                ipv6 |= isinstance(ip, ipaddress.IPv6Address)
                if ip.is_unspecified:
                    return
                exprs.append(ip.exploded)
            else:
                raise ValueError(f"\"{ip}\" is not a valid IP address, network, or IP address range.")

        if exprs:
            if ipv4 and ipv6:
                raise ValueError("Either one of IPv4 or IPv6 can be specified at a time")
            yield {"match": {
                "op": "==",
                "left": {"payload": {"protocol": "ip" if ipv4 else "ip6", "field": "daddr"}},
                "right": exprs[0] if len(exprs) == 1 else {"set": exprs},
            }}

    @staticmethod
    def tcp_dport(*ports: TARGET_PORT_TYPE):
        exprs = []
        for port in ports:
            if port is None:
                return
            elif isinstance(port, tuple) and len(port) == 2 and all(isinstance(x, int) for x in port):
                exprs.append({"range": [str(x) for x in port]})
            elif isinstance(port, int):
                exprs.append(str(port))
            else:
                raise ValueError(f"\"{port}\" is not a valid port or port range.")

        if exprs:
            yield {"match": {
                "op": "==",
                "left": {"payload": {"protocol": "tcp", "field": "dport"}},
                "right": exprs[0] if len(exprs) == 1 else {"set": exprs},
            }}


def to_nftables_rules(targets: list[TARGET_TYPE],
                      listen: list[tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int]]):
    listen4 = next((x for x in listen if isinstance(x[0], ipaddress.IPv4Address)), None)
    listen6 = next((x for x in listen if isinstance(x[0], ipaddress.IPv6Address)), None)

    # see: libnftables-json

    for addr, port in listen:
        yield {
            "family": "ip" if isinstance(addr, ipaddress.IPv4Address) else "ip6",
            "table": "filter",
            "chain": "INPUT",
            "expr": [
                *NftExprGenerators.l4proto("tcp"),
                *NftExprGenerators.ip_daddr(addr),
                *NftExprGenerators.tcp_dport(port),
                {"accept": None}
            ],
        }

    if listen4:
        for target, ports in targets:
            if (not isinstance(target, (ipaddress.IPv4Address, ipaddress.IPv4Network)) and
                    not (isinstance(target, tuple) and isinstance(target[0], ipaddress.IPv4Address))):
                continue
            yield {
                "family": "ip",
                "table": "nat",
                "chain": "PREROUTING",
                "expr": [
                    *NftExprGenerators.l4proto("tcp"),
                    *NftExprGenerators.ip_daddr(target),
                    *NftExprGenerators.tcp_dport(*ports),
                    {"dnat": {"addr": "127.0.0.1" if listen4[0].is_unspecified else listen4[0].exploded,
                              "port": listen4[1]}}
                ]
            }

    if listen6:
        for target, ports in targets:
            if (not isinstance(target, (ipaddress.IPv6Address, ipaddress.IPv6Network)) and
                    not (isinstance(target, tuple) and isinstance(target[0], ipaddress.IPv6Address))):
                continue
            yield {
                "family": "ip6",
                "table": "nat",
                "chain": "PREROUTING",
                "expr": [
                    *NftExprGenerators.l4proto("tcp"),
                    *NftExprGenerators.ip_daddr(target),
                    *NftExprGenerators.tcp_dport(*ports),
                    {"dnat": {"addr": "::1" if listen6[0].is_unspecified else listen6[0].exploded,
                              "port": listen6[1]}}
                ]
            }


def setup_nftables(targets: list[TARGET_TYPE], listen: list[tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int]]):
    rules = list(to_nftables_rules(targets, listen))

    # os.system("nft add chain ip6 filter INPUT")
    proc = subprocess.Popen(["nft", "-a", "-e", "-j", "-f", "-"],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            text=True, encoding="utf-8")
    # res, _ = proc.communicate(input=json.dumps({"nftables": [{"add": {"rule": x}} for x in rules]}))
    res, _ = proc.communicate(input=json.dumps({"nftables": [
        {"add": {"table": {"family": "ip", "name": "filter"}}},
        {"add": {"table": {"family": "ip", "name": "nat"}}},
        {"add": {"table": {"family": "ip6", "name": "filter"}}},
        {"add": {"table": {"family": "ip6", "name": "nat"}}},
        {"add": {"chain": {"family": "ip", "table": "filter", "name": "INPUT"}}},
        {"add": {"chain": {"family": "ip", "table": "nat", "name": "PREROUTING"}}},
        {"add": {"chain": {"family": "ip6", "table": "filter", "name": "INPUT"}}},
        {"add": {"chain": {"family": "ip6", "table": "nat", "name": "PREROUTING"}}},
        *({"add": {"rule": x}} for x in rules)
    ]}))
    if proc.returncode:
        raise RootRequiredError
    res = json.loads(res)

    yield f"nft -j -f - <<< {shlex.quote(json.dumps({"nftables": [
        {"delete": x["add"]} for x in res["nftables"] if all(y not in x["add"] for y in ("table", "chain")) 
    ]}))}\n"


def setup_iptables(targets: list[TARGET_TYPE], listen: list[tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int]]):
    listen4 = next((x for x in listen if isinstance(x[0], ipaddress.IPv4Address)), None)
    listen6 = next((x for x in listen if isinstance(x[0], ipaddress.IPv6Address)), None)
    rules4 = list[str]()
    rules6 = list[str]()
    for target, ports in targets:
        if isinstance(target, tuple):
            addr_rule = f"-m iprange --dst-range {target[0]}-{target[1]}"
            use_ipv4 = isinstance(target[0], ipaddress.IPv4Address)
            use_ipv6 = isinstance(target[0], ipaddress.IPv6Address)
        elif target.prefixlen > 0:
            addr_rule = f"-d {target}"
            use_ipv4 = isinstance(target, (ipaddress.IPv4Address, ipaddress.IPv4Network))
            use_ipv6 = isinstance(target, (ipaddress.IPv6Address, ipaddress.IPv6Network))
        else:
            addr_rule = ""
            use_ipv4 = use_ipv6 = True

        port_rule = []
        for port in ports:
            if port is None:
                port_rule = ""
                break
            elif isinstance(port, tuple):
                port_rule.append(f"{port[0]}:{port[1]}")
            elif isinstance(port, int):
                port_rule.append(str(port))
            else:
                raise AssertionError
        else:
            port_rule = f"-m multiport --dports {",".join(port_rule)}"

        if use_ipv4 and listen4:
            if listen4[0].is_unspecified:
                rules4.append(
                    f"PREROUTING -t nat -p tcp {addr_rule} {port_rule} -j DNAT --to 127.0.0.1:{listen4[1]}")
            else:
                rules4.append(
                    f"PREROUTING -t nat -p tcp {addr_rule} {port_rule} -j DNAT --to {listen4[0]}:{listen4[1]}")

        if use_ipv6 and listen6:
            if listen4[0].is_unspecified:
                rules6.append(
                    f"PREROUTING -t nat -p tcp {addr_rule} {port_rule} -j DNAT --to [::1]:{listen6[1]}")
            else:
                rules6.append(
                    f"PREROUTING -t nat -p tcp {addr_rule} {port_rule} -j DNAT --to [{listen6[0]}]:{listen6[1]}")

    for addr, port in listen:
        if isinstance(addr, ipaddress.IPv4Address):
            if addr.is_unspecified:
                rules4.append(f"INPUT -t filter -p tcp --dport {port} -j ACCEPT")
            else:
                rules4.append(f"INPUT -t filter -p tcp -d {addr} --dport {port} -j ACCEPT")
        elif isinstance(addr, ipaddress.IPv6Address):
            if addr.is_unspecified:
                rules6.append(f"INPUT -t filter -p tcp --dport {port} -j ACCEPT")
            else:
                rules6.append(f"INPUT -t filter -p tcp -d {addr} --dport {port} -j ACCEPT")

    for rule in rules4:
        cmd = f"iptables -I {rule}"
        print(cmd)
        if os.system(cmd):
            raise RootRequiredError
        yield f"iptables -D {rule}\n"

    for rule in rules6:
        cmd = f"ip6tables -I {rule}"
        print(cmd)
        if os.system(cmd):
            raise RootRequiredError
        yield f"ip6tables -D {rule}\n"


def get_sysctl(var_name: str):
    return os.popen(f"sysctl {var_name}").read().split("=", 1)[1].strip()


def setup_sysctl():
    for k, v in SYSCTL_VARS.items():
        v_old = get_sysctl(k)
        os.system(f"sysctl -w {k}={v}")
        yield f"sysctl -w {k}={v_old}\n"


def setup_system_configuration(targets: list[TARGET_TYPE],
                               firewall: str,
                               write_sysctl: bool,
                               sockets: list[socket.socket]):
    addr_tuples = [(ipaddress.ip_address(x), y) for x, y, *_ in [x.getsockname() for x in sockets]]
    match firewall:
        case "nftables":
            yield from setup_nftables(targets, addr_tuples)
        case "iptables":
            yield from setup_iptables(targets, addr_tuples)
        case "none":
            pass
        case _:
            raise AssertionError

    if write_sysctl:
        yield from setup_sysctl()
