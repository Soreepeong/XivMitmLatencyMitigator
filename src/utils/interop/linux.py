import ipaddress
import json
import os
import shlex
import subprocess
import typing

from utils.consts import SYSCTL_VARS
from utils.exceptions import RootRequiredError

TARGET_ADDRESS_TYPE = typing.Union[
    ipaddress.IPv4Network,
    ipaddress.IPv4Address,
    tuple[ipaddress.IPv4Address, ipaddress.IPv4Address],
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
        for ip in ips:
            if ip is None:
                return
            elif isinstance(ip, tuple) and len(ip) == 2:
                exprs.append({"range": [str(x) for x in ip]})
            elif isinstance(ip, ipaddress.IPv4Network):
                if ip.is_unspecified or ip.prefixlen == 0:
                    return
                elif ip.prefixlen == ip.max_prefixlen:
                    exprs.append(ip.network_address.exploded)
                else:
                    exprs.append({"prefix": {"addr": ip.network_address.exploded, "len": ip.prefixlen}})
            elif isinstance(ip, ipaddress.IPv4Address):
                if ip.is_unspecified:
                    return
                exprs.append(ip.exploded)
            else:
                raise ValueError(f"\"{ip}\" is not a valid IP address, network, or IP address range.")

        if exprs:
            yield {"match": {
                "op": "==",
                "left": {"payload": {"protocol": "ip", "field": "daddr"}},
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


def to_nftables_rules(targets: list[TARGET_TYPE], listen_addr: ipaddress.IPv4Address, listen_port: int):
    # see: libnftables-json
    yield {
        "family": "ip",
        "table": "filter",
        "chain": "INPUT",
        "expr": [
            *NftExprGenerators.l4proto("tcp"),
            *NftExprGenerators.ip_daddr(listen_addr),
            *NftExprGenerators.tcp_dport(listen_port),
            {"accept": None}
        ],
    }

    for target, ports in targets:
        yield {
            "family": "ip",
            "table": "nat",
            "chain": "PREROUTING",
            "expr": [
                *NftExprGenerators.l4proto("tcp"),
                *NftExprGenerators.ip_daddr(target),
                *NftExprGenerators.tcp_dport(*ports),
                {"dnat": {"addr": "127.0.0.1" if listen_addr.is_unspecified else listen_addr.exploded,
                          "port": listen_port}}
            ]
        }


def setup_nftables(targets: list[TARGET_TYPE], listen_addr: ipaddress.IPv4Address, listen_port: int):
    rules = to_nftables_rules(targets, listen_addr, listen_port)

    proc = subprocess.Popen(["nft", "-a", "-e", "-j", "-f", "-"],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            text=True, encoding="utf-8")
    res, _ = proc.communicate(input=json.dumps({"nftables": [{"add": {"rule": x}} for x in rules]}))
    if proc.returncode:
        raise RootRequiredError
    res = json.loads(res)

    yield f"nft -j -f - <<< {shlex.quote(json.dumps({"nftables": [{"delete": x["add"]} for x in res["nftables"]]}))}\n"


def setup_iptables(targets: list[TARGET_TYPE], listen_addr: ipaddress.IPv4Address, listen_port: int):
    rules = list[str]()
    for target, ports in targets:
        if isinstance(target, tuple):
            addr_rule = f"-m iprange --dst-range {target[0]}-{target[1]}"
        elif target.prefixlen > 0:
            addr_rule = f"-d {target}"
        else:
            addr_rule = ""

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
                assert False
        else:
            port_rule = f"-m multiport --dports {",".join(port_rule)}"

        if listen_addr.is_unspecified:
            rules.append(
                f"PREROUTING -t nat -p tcp {addr_rule} {port_rule} -j DNAT --to 127.0.0.1:{listen_port}")
        else:
            rules.append(
                f"PREROUTING -t nat -p tcp {addr_rule} {port_rule} -j DNAT --to {listen_addr}:{listen_port}")

    if listen_addr.is_unspecified:
        rules.append(f"INPUT -t filter -p tcp --dport {listen_port} -j ACCEPT")
    else:
        rules.append(f"INPUT -t filter -p tcp -d {listen_addr} --dport {listen_port} -j ACCEPT")

    for rule in rules:
        cmd = f"iptables -I {rule}"
        print(cmd)
        if os.system(cmd):
            raise RootRequiredError
        yield f"iptables -D {rule}\n"


def get_sysctl(var_name: str):
    return os.popen(f"sysctl {var_name}").read().split("=", 1)[1].strip()


def setup_sysctl():
    for k, v in SYSCTL_VARS.items():
        v_old = get_sysctl(k)
        os.system(f"sysctl -w {k}={v}")
        yield f"sysctl -w {k}={v_old}\n"


def setup_system_configuration(targets: list[TARGET_TYPE], firewall: str, write_sysctl: bool,
                               listen_address: ipaddress.IPv4Address, listen_port: int):
    match firewall:
        case "nftables":
            yield from setup_nftables(targets, listen_address, listen_port)
        case "iptables":
            yield from setup_iptables(targets, listen_address, listen_port)
        case "none":
            pass
        case _:
            raise AssertionError

    if write_sysctl:
        yield from setup_sysctl()
