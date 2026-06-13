import argparse
import dataclasses
import json
import os

from utils.icmp_race import FindBestInterfaceConfig


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
        raise ValueError("Extra delay cannot be a negative number.")

    return args
