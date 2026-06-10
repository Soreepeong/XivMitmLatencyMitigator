import collections
import ipaddress
import json
import os
import random
import re
import shlex
import socket
import subprocess

from utils.consts import SYSCTL_VARS, NFTABLES_TABLE_NAME
from utils.exceptions import SubprocessFailedError
from utils.misc import TARGET_TYPE, TARGET_PORT_TYPE, TARGET_ADDRESS_TYPE, is_ipv6


def get_all_local_addresses(devname: str = None):
    with subprocess.Popen(
            ["ip", "address", "show"] if devname is None else ["ip", "address", "show", "dev", devname],
            stdout=subprocess.PIPE,
            text=True) as proc:
        res, _ = proc.communicate()
        SubprocessFailedError.raise_if_nonzero(proc.returncode)
        for x in res.splitlines():
            if "inet" in x:
                addr, prefix = x.strip().split(" ", 2)[1].split("/", 1)
                yield ipaddress.ip_address(addr), prefix


def clear_if_addrs(if_name: str):
    for addr, prefix in get_all_local_addresses(if_name):
        SubprocessFailedError.call_or_raise(f"ip address delete {addr}/{prefix} dev {if_name}")


def setup_dummy_adapter(if_name: str, *addrs: ipaddress.IPv4Address | ipaddress.IPv6Address, clear_addrs: bool = True):
    if clear_addrs:
        clear_if_addrs(if_name)

    local_addresses = [addr for addr, _ in get_all_local_addresses()]
    for addr in addrs:
        if addr.is_unspecified:
            if isinstance(addr, ipaddress.IPv4Address):
                lo = int(ipaddress.IPv4Address("169.254.1.0"))
                hi = int(ipaddress.IPv4Address("169.254.254.255"))
                while True:
                    addr = ipaddress.IPv4Address(random.randint(lo, hi))
                    if addr not in local_addresses:
                        break
            elif isinstance(addr, ipaddress.IPv6Address):
                lo = int(ipaddress.IPv6Address("fe80::"))
                hi = int(ipaddress.IPv6Address("febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff"))
                while True:
                    addr = ipaddress.IPv6Address(random.randint(lo, hi))
                    if addr not in local_addresses:
                        break
            else:
                raise ValueError

        SubprocessFailedError.call_or_raise(f"ip address add {addr} dev {if_name} scope link")
        yield addr


class NftExprGenerators:
    @staticmethod
    def l4proto(proto: str):
        yield {"match": {"op": "==", "left": {"meta": {"key": "l4proto"}}, "right": proto}}

    @staticmethod
    def nfproto(proto: str):
        yield {"match": {"op": "==", "left": {"meta": {"key": "nfproto"}}, "right": proto}}

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
                    yield from NftExprGenerators.nfproto("ipv4" if ipv4 else "ipv6")
                    return
                elif ip.prefixlen == ip.max_prefixlen:
                    exprs.append(ip.network_address.exploded)
                else:
                    exprs.append({"prefix": {"addr": ip.network_address.exploded, "len": ip.prefixlen}})
            elif isinstance(ip, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
                ipv4 |= isinstance(ip, ipaddress.IPv4Address)
                ipv6 |= isinstance(ip, ipaddress.IPv6Address)
                if ip.is_unspecified:
                    yield from NftExprGenerators.nfproto("ipv4" if ipv4 else "ipv6")
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


def to_nftables_rules(targets: collections.abc.Iterable[TARGET_TYPE],
                      listen: collections.abc.Iterable[tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int]],
                      nftables_meta_mark: int):
    listen4 = next((x for x in listen if isinstance(x[0], ipaddress.IPv4Address)), (None, None))
    listen6 = next((x for x in listen if isinstance(x[0], ipaddress.IPv6Address)), (None, None, None, None))

    # see: libnftables-json

    for addr, port in listen:
        yield {
            "family": "inet",
            "table": NFTABLES_TABLE_NAME,
            "chain": "INPUT",
            "expr": [
                *NftExprGenerators.l4proto("tcp"),
                *NftExprGenerators.ip_daddr(addr),
                *NftExprGenerators.tcp_dport(port),
                {"mangle": {"key": {"meta": {"key": "mark"}}, "value": nftables_meta_mark}},
                {"accept": None}
            ],
        }

    for target, ports in targets:
        ipv6 = is_ipv6(target)
        laddr, lport = listen6 if ipv6 else listen4
        if laddr is None:
            continue
        yield {
            "family": "inet",
            "table": NFTABLES_TABLE_NAME,
            "chain": "PREROUTING",
            "expr": [
                *NftExprGenerators.l4proto("tcp"),
                *NftExprGenerators.ip_daddr(target),
                *NftExprGenerators.tcp_dport(*ports),
                {"mangle": {"key": {"meta": {"key": "mark"}}, "value": nftables_meta_mark}},
                {"dnat": {"addr": laddr.exploded, "port": lport}},
            ]
        }


def setup_nftables(targets: collections.abc.Iterable[TARGET_TYPE],
                   listen: collections.abc.Iterable[tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int]],
                   nftables_meta_mark: int):
    with subprocess.Popen(["nft", "-j", "-f", "-"], stdin=subprocess.PIPE, text=True) as proc:
        res, _ = proc.communicate(input=json.dumps({"nftables": [
            {"add": {"table": {"family": "inet", "name": NFTABLES_TABLE_NAME}}},
            {"add": {"chain": {"family": "inet", "table": NFTABLES_TABLE_NAME, "name": "INPUT",
                               "type": "filter", "hook": "input", "prio": -1, "policy": "accept"}}},
            {"add": {"chain": {"family": "inet", "table": NFTABLES_TABLE_NAME, "name": "PREROUTING",
                               "type": "nat", "hook": "prerouting", "prio": -101, "policy": "accept"}}},
            *({"add": {"rule": x}} for x in to_nftables_rules(targets, listen, nftables_meta_mark))
        ]}))
        SubprocessFailedError.raise_if_nonzero(proc.returncode)

    yield f"nft -j -f - <<< {shlex.quote(json.dumps({"nftables": [
        {"flush": {"table": {"family": "inet", "name": NFTABLES_TABLE_NAME}}},
        {"delete": {"table": {"family": "inet", "name": NFTABLES_TABLE_NAME}}},
    ]}))}\n"


def setup_iptables(targets: collections.abc.Iterable[TARGET_TYPE],
                   listen: collections.abc.Iterable[tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int]]):
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
            rules4.append(
                f"PREROUTING -t nat -p tcp {addr_rule} {port_rule} -j DNAT --to {listen4[0]}:{listen4[1]}")

        if use_ipv6 and listen6:
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
        SubprocessFailedError.call_or_raise(cmd)
        yield f"iptables -D {rule}\n"

    for rule in rules6:
        cmd = f"ip6tables -I {rule}"
        SubprocessFailedError.call_or_raise(cmd)
        yield f"ip6tables -D {rule}\n"


def get_sysctl(var_name: str):
    with subprocess.Popen(["sysctl", var_name], stdout=subprocess.PIPE, text=True, shell=True) as proc:
        res, _ = proc.communicate()
        SubprocessFailedError.raise_if_nonzero(proc.returncode)
        return res.split("=", 1)[1].strip()


def get_ping_group_range() -> tuple[int, int] | None:
    """Return the current (low, high) net.ipv4.ping_group_range, or None if it cannot be read."""
    try:
        with subprocess.Popen(["sysctl", "-n", "net.ipv4.ping_group_range"],
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True) as proc:
            res, _ = proc.communicate()
        if proc.returncode != 0:
            return None
        low, high = (int(x) for x in res.split())
        return low, high
    except (OSError, ValueError):
        return None


def setup_sysctl(extra_vars: dict | None = None):
    sysctl_vars = {**SYSCTL_VARS, **(extra_vars or {})}
    with subprocess.Popen(["sysctl", *sysctl_vars.keys()], stdout=subprocess.PIPE, text=True) as proc:
        res, _ = proc.communicate()
        SubprocessFailedError.raise_if_nonzero(proc.returncode)
        yield " ".join(shlex.quote(x) for x in [
            "sysctl",
            "-q",
            "-w",
            *re.sub(r'\s*=\s*', '=', res).splitlines(),
        ]) + "\n"

    with subprocess.Popen(["sysctl", "-q", "-w", *(f"{k}={v}" for k, v in sysctl_vars.items())]) as proc:
        proc.communicate()
        SubprocessFailedError.raise_if_nonzero(proc.returncode)


def setup_system_configuration(targets: collections.abc.Iterable[TARGET_TYPE],
                               firewall: str,
                               nftables_meta_mark: int,
                               write_sysctl: bool,
                               sockets: collections.abc.Iterable[socket.socket],
                               serve_gid: int | None = None):
    addr_tuples = [(ipaddress.ip_address(x), port) for x, port, *_ in [x.getsockname() for x in sockets]]

    match firewall:
        case "nftables":
            yield from setup_nftables(targets, addr_tuples, nftables_meta_mark)
        case "iptables":
            yield from setup_iptables(targets, addr_tuples)
        case "none":
            pass
        case _:
            raise AssertionError

    if write_sysctl:
        extra_sysctl_vars = {}
        if serve_gid is not None:
            # Permit the unprivileged serving group to open ICMP ping sockets for latency probing.
            # Only touch the system-wide range when the serving group is not already allowed, and
            # then *widen* the existing range instead of replacing it — replacing it would revoke
            # other users' (e.g. the login user's) ability to use ICMP ping at all.
            current = get_ping_group_range()
            if current is not None:
                low, high = current
                if low > high:
                    # Disabled range (low > high): enable exactly the serving group.
                    extra_sysctl_vars["net.ipv4.ping_group_range"] = f"{serve_gid} {serve_gid}"
                elif not low <= serve_gid <= high:
                    extra_sysctl_vars["net.ipv4.ping_group_range"] = \
                        f"{min(low, serve_gid)} {max(high, serve_gid)}"
        yield from setup_sysctl(extra_sysctl_vars)
