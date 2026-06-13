#!/usr/bin/sudo python
import argparse
import asyncio
import contextlib
import dataclasses
import grp
import io
import ipaddress
import json
import logging.handlers
import os
import pathlib
import pwd
import signal
import socket
import stat
import subprocess
import sys
import time
import typing

from connections.manager import ConnectionManager
from utils.consts import DUMMY_NET_NAME, CLEANUP_FILE_NAME
from utils.exceptions import SubprocessFailedError
from utils.icmp_race import FindBestInterfaceConfig
from utils.interop.linux import TARGET_TYPE, setup_system_configuration, setup_dummy_adapter
from utils.interop.oodle import OodleWithBudgetAbiThunks, test_oodle
from utils.interop.win32 import POINTER_SIZE
from utils.interop.xivalex import load_definitions, OpcodeDefinition, MitigationConfig
from utils.interop.zipatch import download_exes
from utils.misc import format_addr_port, dedup_targets, generate_nat64_targets, listener_from_address, \
    getaddrinfo_for_tcp_with_port


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
    upstream_interfaces: list[str] = dataclasses.field(default_factory=list)
    icmp_attempts: int = 7
    icmp_interval_min: float = 0.1
    icmp_interval_max: float = 0.3
    icmp_penalties: list[str] = dataclasses.field(default_factory=list)
    icmp_debug: bool = False
    icmp_cache_ttl: float = 30.0
    mitigate_dry_run: bool = False
    working_directory: str = ""
    dummy_addr4: str = "0.0.0.0"
    dummy_addr6: str = "::0"
    nftables_meta_mark: int = 0xFF14EE03
    nat64: str = "none"
    dns_lookup_timeout: float = 30
    serve_as: str = "nobody"
    cleanup_directory: str = "/tmp/xivmitm-cleanup"


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


def load_arguments() -> ArgumentTuple:
    parser = argparse.ArgumentParser("XivMitmLatencyMitigator",
                                     description="https://github.com/Soreepeong/XivMitmLatencyMitigator")

    # Resolve -c/--config first so its values become the defaults for every other argument,
    # letting explicit command-line arguments still override the config file.
    config_pre_parser = argparse.ArgumentParser(add_help=False)
    config_pre_parser.add_argument("-c", "--config", dest="config", default=None)
    config_path = config_pre_parser.parse_known_args()[0].config

    defaults = ArgumentTuple()
    if config_path is not None:
        try:
            defaults = load_config_into(defaults, config_path)
        except Exception as e:
            raise RuntimeError(f"Failed to load config {config_path!r}") from e

    parser.add_argument("-c", "--config", action="store", dest="config", default=None,
                        help="Load options from a JSON config file. Any field listed in config.example.json "
                             "may be set; command-line arguments override config file values.")
    parser.add_argument("-t", "--target", action="append",
                        dest="targets", default=defaults.targets,
                        help="Target host names or IPv4 addresses to take over, optionally with prefix length.")
    parser.add_argument("-l", "--listen", action="append",
                        dest="listen", default=defaults.listen,
                        help="IP address and port to listen to.")
    parser.add_argument("-f", "--firewall", action="store",
                        dest="firewall", default=defaults.firewall, choices=["none", "iptables", "nftables"],
                        help="Firewall to use to enable NAT towards this application.")
    parser.add_argument("-i", "--interface", action="append",
                        dest="upstream_interfaces", default=defaults.upstream_interfaces,
                        help="Specify which interface to use for upstream connections. May be specified multiple times.")
    parser.add_argument("--icmp-attempts", action="store", type=int,
                        dest="icmp_attempts", default=defaults.icmp_attempts,
                        help="Number of ICMP echo probes per interface when choosing the best upstream interface. "
                             "Only used when more than one -i interface is given.")
    parser.add_argument("--icmp-interval-min", action="store", type=float,
                        dest="icmp_interval_min", default=defaults.icmp_interval_min,
                        help="Minimum delay in seconds between consecutive ICMP echo probes.")
    parser.add_argument("--icmp-interval-max", action="store", type=float,
                        dest="icmp_interval_max", default=defaults.icmp_interval_max,
                        help="Maximum delay in seconds between consecutive ICMP echo probes.")
    parser.add_argument("--icmp-penalty", action="append", metavar="REGEX=MS",
                        dest="icmp_penalties", default=defaults.icmp_penalties,
                        help="Add a score penalty in milliseconds to interfaces whose name matches REGEX, "
                             "e.g. '^wg-.*=5'. May be specified multiple times.")
    parser.add_argument("--icmp-debug", action="store_true",
                        dest="icmp_debug", default=defaults.icmp_debug,
                        help="Log per-probe ICMP measurement details when choosing the best interface.")
    parser.add_argument("--icmp-cache-ttl", action="store", type=float,
                        dest="icmp_cache_ttl", default=defaults.icmp_cache_ttl,
                        help="Seconds to cache the chosen best interface per destination IP, so a "
                             "session's multiple connections to one server reuse a single measurement. "
                             "0 disables caching.")
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
    parser.add_argument("--mitigate-dry-run", action="store_true",
                        dest="mitigate_dry_run", default=defaults.mitigate_dry_run,
                        help="Do not actually apply any mitigation, just print what would have happened.")
    parser.add_argument("--dummy-addr4", action="store",
                        dest="dummy_addr4", default=defaults.dummy_addr4,
                        help="Dummy IPv4 address for redirecting to this application's socket.")
    parser.add_argument("--dummy-addr6", action="store",
                        dest="dummy_addr6", default=defaults.dummy_addr6,
                        help="Dummy IPv6 address for redirecting to this application's socket.")
    parser.add_argument("--nftables-meta-mark", action="store", type=int,
                        dest="nftables_meta_mark", default=defaults.nftables_meta_mark,
                        help="Meta mark to set for packets that should be accepted. Useful if there are other tables utilizing drop policy.")
    parser.add_argument("--nat64", action="store",
                        dest="nat64", default=defaults.nat64, choices=["none", "wrap", "unwrap"],
                        help="NAT64 preference mode.")
    parser.add_argument("--dns-lookup-timeout", action="store", type=float,
                        dest="dns_lookup_timeout", default=defaults.dns_lookup_timeout,
                        help="DNS lookup timeout, if the DNS server was unreachable.")
    parser.add_argument("--serve-as", action="store",
                        dest="serve_as", default=defaults.serve_as,
                        help="setuid/gid to the specified user(:group) before starting to serve.")
    parser.add_argument("--cleanup-directory", action="store",
                        dest="cleanup_directory", default=defaults.cleanup_directory,
                        help="Directory to store per-process cleanup scripts. On startup, "
                             "cleanup scripts left behind by no-longer-running processes are run "
                             "and removed.")

    parsed = vars(parser.parse_args())
    parsed.pop("config", None)
    args = ArgumentTuple(**parsed)

    if args.working_directory == "":
        args.working_directory = os.getcwd()

    if args.extra_delay < 0:
        logging.warning("Extra delay cannot be a negative number.")
        return -1

    return args


def get_listen_sockaddrs(args: ArgumentTuple, getaddrinfo):
    sockaddrs = []
    for x in setup_dummy_adapter(
            DUMMY_NET_NAME, ipaddress.IPv4Address(args.dummy_addr4), ipaddress.IPv6Address(args.dummy_addr6)):
        if isinstance(x, ipaddress.IPv4Address):
            yield from getaddrinfo(str(x), 0, socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        elif isinstance(x, ipaddress.IPv6Address):
            yield from getaddrinfo(f"{x}%{DUMMY_NET_NAME}", 0, socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        else:
            raise AssertionError
    for x in args.listen:
        yield from getaddrinfo_for_tcp_with_port(x, getaddrinfo)
    return sockaddrs


def get_definitions(args: ArgumentTuple) -> list[OpcodeDefinition]:
    if "off" in args.regions:
        return []

    definitions = load_definitions(args.working_directory, args.update_opcodes, args.opcode_json_path)
    if args.regions and (args.opcode_json_path is None or args.opcode_json_path.strip() == ""):
        definitions = [x for x in definitions if any(r.lower() in x.Name.lower() for r in args.regions)]
    return definitions


def load_config_into(base: ArgumentTuple, path: str) -> ArgumentTuple:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("config file must contain a JSON object")
    valid = {f.name for f in dataclasses.fields(ArgumentTuple)}
    unknown = sorted(k for k in data if k not in valid)
    if unknown:
        raise ValueError(f"unknown config keys: {', '.join(unknown)}")
    return dataclasses.replace(base, **data)


def build_icmp_config(args: ArgumentTuple) -> FindBestInterfaceConfig:
    penalties: dict[str, float] = {}
    for item in args.icmp_penalties:
        pattern, sep, value = item.rpartition("=")
        if not sep or not pattern:
            raise ValueError(f"Invalid --icmp-penalty {item!r}; expected REGEX=MS, e.g. '^wg-.*=5'")
        penalties[pattern] = float(value)
    return FindBestInterfaceConfig(
        num_attempts=args.icmp_attempts,
        interval=(args.icmp_interval_min, args.icmp_interval_max),
        penalties=penalties,
        debug=args.icmp_debug,
        cache_ttl=args.icmp_cache_ttl,
    )


def get_setuidgid(name: str) -> tuple[int | None, int | None]:
    if name == "":
        return None, None

    serve_as = name.split(":")
    if len(serve_as) == 1:
        t = pwd.getpwnam(serve_as[0])
        return t.pw_uid, t.pw_gid
    elif len(serve_as) == 2:
        return pwd.getpwnam(serve_as[0]).pw_uid, grp.getgrnam(serve_as[1]).gr_gid
    else:
        raise ValueError("must be in the format of username:groupname, if not username only")


def wait_for_child_shutdown(pid: int) -> int:
    while True:
        try:
            return os.waitpid(pid, 0)[1]
        except ChildProcessError:
            return 0
        except KeyboardInterrupt:
            break

    with contextlib.suppress(ProcessLookupError):
        os.kill(pid, signal.SIGTERM)

    deadline = time.monotonic() + 5
    killed = False
    while True:
        try:
            reaped, status = os.waitpid(pid, os.WNOHANG)
            if reaped != 0:
                return status
            if not killed and time.monotonic() >= deadline:
                killed = True
                with contextlib.suppress(ProcessLookupError):
                    os.kill(pid, signal.SIGKILL)
            time.sleep(0.05)
        except ChildProcessError:
            return 0
        except KeyboardInterrupt:
            with contextlib.suppress(ProcessLookupError):
                os.kill(pid, signal.SIGTERM)


def read_ffxiv_bytes(args: ArgumentTuple) -> bytes | None:
    if "off" not in args.regions:
        ffxiv_exe_filepath = os.path.join(args.working_directory, "ffxiv.exe")
        ffxiv_dx11_exe_filepath = os.path.join(args.working_directory, "ffxiv_dx11.exe")
        if POINTER_SIZE == 4:
            if not os.path.exists(ffxiv_exe_filepath):
                raise RuntimeError("Need ffxiv.exe in the same directory. "
                                   "Copy one from your local Windows/Mac installation.")

            return pathlib.Path(ffxiv_exe_filepath).read_bytes()
        elif POINTER_SIZE == 8:
            if not os.path.exists(ffxiv_dx11_exe_filepath):
                raise RuntimeError("Need ffxiv_dx11.exe in the same directory. "
                                   "Copy one from your local Windows/Mac installation.")

            return pathlib.Path(ffxiv_dx11_exe_filepath).read_bytes()
        else:
            raise RuntimeError("Platform not supported. Only x86 and x64 systems are supported.")
    return None


def setup_cleanup_file(args: ArgumentTuple) -> tuple[str, io.TextIOWrapper]:
    cleanup_dir = pathlib.Path(args.cleanup_directory)

    euid = os.geteuid()
    os.makedirs(cleanup_dir, mode=0o755, exist_ok=True)
    os.chmod(cleanup_dir, 0o755)  # normalize regardless of the inherited umask

    info = os.stat(cleanup_dir, follow_symlinks=False)
    if not stat.S_ISDIR(info.st_mode):
        raise RuntimeError(f"Cleanup directory {cleanup_dir} is not a directory.")

    if info.st_uid != euid:
        raise RuntimeError(f"Cleanup directory {cleanup_dir} is owned by uid {info.st_uid}, not the current "
                           f"uid {euid}; refusing to run scripts from it. Remove it and retry.")
    if info.st_mode & 0o022:
        raise RuntimeError(f"Cleanup directory {cleanup_dir} is writable by group/other "
                           f"(mode {stat.S_IMODE(info.st_mode):04o}); refusing to run scripts from it. "
                           f"Run `chmod 0755 {cleanup_dir}` or remove it and retry.")

    for f in cleanup_dir.iterdir():
        if os.access(f, os.X_OK):
            logging.info(f"Stale cleanup: Running {f.name}")
            with contextlib.suppress(OSError):
                subprocess.call([f.resolve()], shell=True)

    cleanup_file = cleanup_dir / CLEANUP_FILE_NAME
    return (str(cleanup_file.resolve()),
            open(cleanup_file, "w", opener=lambda path, flags: os.open(path, flags, 0o755)))


def __main__() -> int:
    try:
        signal.signal(signal.SIGTERM, signal.default_int_handler)
        logging.basicConfig(level=logging.INFO, force=True,
                            format="%(asctime)s\t%(process)d(main)\t%(levelname)s\t%(message)s",
                            handlers=[
                                logging.StreamHandler(sys.stderr),
                            ])

        args = load_arguments()

        if sys.platform != 'linux':
            raise RuntimeError("This script only runs on Linux.")

        icmp_config = build_icmp_config(args)

        download_exes(*args.ffxiv_exe_urls)
        definitions = get_definitions(args)
        uid, gid = get_setuidgid(args.serve_as)

        getaddrinfo = create_getaddrinfo_with_timeout(args.dns_lookup_timeout)

        targets = [
            *parse_args_targets(args.targets, getaddrinfo),
            *parse_opcode_definitions(definitions),
        ]

        if len(targets) == 0:
            targets.append(ipaddress.IPv4Address("0.0.0.0/0"))
            targets.append(ipaddress.IPv6Address("::0/0"))

        try:
            cleanup_filepath, cleanup_fp = setup_cleanup_file(args)
        except Exception as e:
            raise RuntimeError(f"Failed to setup cleanup file") from e

        pid = os.fork()
        if pid != 0:
            cleanup_fp.close()
            try:
                logging.info("Press Ctrl+C to quit.")
                return wait_for_child_shutdown(pid)
            finally:
                logging.info("Cleaning up...")
                with contextlib.suppress(OSError, KeyboardInterrupt):
                    subprocess.call([cleanup_filepath], shell=True)

        logging.basicConfig(level=logging.INFO, force=True,
                            format="%(asctime)s\t%(process)d(child)\t%(levelname)s\t%(message)s",
                            handlers=[
                                logging.StreamHandler(sys.stderr),
                            ])

        ffxiv_bytes = read_ffxiv_bytes(args)

        with cleanup_fp:
            cleanup_fp.writelines((
                "#!/bin/sh\n"
                f'if [ "$1" != "--force" ] && kill -0 {os.getpid()} 2>/dev/null; then\n'
                "    exit 0\n"
                "fi\n"
            ))

            # https://serverfault.com/questions/975558/nftables-ip6-route-to-localhost-ipv6-nat-to-loopback
            cleanup_fp.write(f"ip link delete {DUMMY_NET_NAME}\n")
            SubprocessFailedError.call_or_raise(f"ip link add {DUMMY_NET_NAME} type dummy")
            SubprocessFailedError.call_or_raise(f"ip link set {DUMMY_NET_NAME} up")

            listeners = list(listener_from_address(*y) for y in get_listen_sockaddrs(args, getaddrinfo))
            if any(x.family == socket.AF_INET6 for x in listeners):
                targets.extend(generate_nat64_targets(targets))
            targets = dedup_targets(targets)

            cleanup_fp.writelines(setup_system_configuration(
                targets, args.firewall, args.nftables_meta_mark, args.write_sysctl, listeners, gid))

            cleanup_fp.write('rm -f -- "$0"\n')

        for listener in listeners:
            listener.listen()
            logging.info(f"Listening on: {format_addr_port(*listener.getsockname())}")

        if gid is not None:
            os.setgid(gid)
        if uid is not None:
            os.setuid(uid)

        if ffxiv_bytes is not None:
            OodleWithBudgetAbiThunks.init_module(ffxiv_bytes)
            test_oodle()

        asyncio.run(ConnectionManager(
            listeners,
            args.upstream_interfaces,
            args.enable_web_statistics,
            args.nat64,
            MitigationConfig(
                args.mitigate_dry_run,
                args.measure_ping,
                args.extra_delay,
                definitions,
            ),
            icmp_config,
        ).serve_forever())
        return 0
    except SubprocessFailedError as e:
        logging.error(str(e))
        return e.code
    except KeyboardInterrupt:
        return 0
    except ValueError as e:
        logging.error(str(e))
        return -1


if __name__ == "__main__":
    exit(__main__())
