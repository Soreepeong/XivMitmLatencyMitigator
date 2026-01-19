import ipaddress
import os

from utils.consts import SYSCTL_VARS
from utils.exceptions import RootRequiredError

TARGET_TYPE = tuple[
    ipaddress.IPv4Network | tuple[ipaddress.IPv4Address, ipaddress.IPv4Address],
    list[int | tuple[int, int] | None]
]


def get_sysctl(var_name: str):
    return os.popen(f"sysctl {var_name}").read().split("=", 1)[1].strip()


def setup_nftables(targets: list[TARGET_TYPE], listen_addr: str, listen_port: int):
    rules = list[str]()
    for target, ports in targets:
        if isinstance(target, tuple):
            addr_rule = f"ip daddr {target[0]}-{target[1]}"
        elif target.prefixlen > 0:
            addr_rule = f"ip daddr {target}"
        else:
            addr_rule = ""

        port_rule = []
        for port in ports:
            if port is None:
                port_rule = ""
                break
            elif isinstance(port, tuple):
                port_rule.append(f"{port[0]}-{port[1]}")
            elif isinstance(port, int):
                port_rule.append(str(port))
            else:
                assert False
        else:
            port_rule = f"tcp dport {{ {",".join(port_rule)} }}"

        if listen_addr == "0.0.0.0":
            rules.append(f"ip nat PREROUTING meta l4proto tcp {addr_rule} {port_rule} dnat 127.0.0.1:{listen_port}")
        else:
            rules.append(f"ip nat PREROUTING meta l4proto tcp {addr_rule} {port_rule} dnat {listen_addr}:{listen_port}")

    if listen_addr == "0.0.0.0":
        rules.append(f"ip filter INPUT tcp dport {listen_port} accept")
    else:
        rules.append(f"ip filter INPUT ip daddr {listen_addr} tcp dport {listen_port} accept")

    for rule in rules:
        cmd = f"nft -a -e add rule {rule}"
        res = os.popen(cmd)
        out = res.read()
        print(out)
        h = out.strip().split("\n")[0].split(" ")[-1]
        if res.close():
            raise RootRequiredError
        yield f"nft delete rule {' '.join(rule.split(' ')[:3])} handle {h}\n"


def setup_iptables(targets: list[TARGET_TYPE], listen_addr: str, listen_port: int):
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

        rules.append(
            f"PREROUTING -t nat -p tcp {addr_rule} {port_rule} -j DNAT --to-destination {listen_addr}:{listen_port}")

    if listen_addr == "0.0.0.0":
        rules.append(f"INPUT -t filter -p tcp --dport {listen_port} -j ACCEPT")
    else:
        rules.append(f"INPUT -t filter -p tcp -d {listen_addr} --dport {listen_port} -j ACCEPT")

    for rule in rules:
        cmd = f"iptables -I {rule}"
        print(cmd)
        if os.system(cmd):
            raise RootRequiredError
        yield f"iptables -D {rule}\n"


def setup_sysctl():
    for k, v in SYSCTL_VARS.items():
        v_old = get_sysctl(k)
        os.system(f"sysctl -w {k}={v}")
        yield f"sysctl -w {k}={v_old}\n"


def setup_system_configuration(targets: list[TARGET_TYPE], firewall: str, write_sysctl: bool,
                               listen_address: str, listen_port: int):
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
