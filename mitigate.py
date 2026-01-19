#!/usr/bin/sudo python
import argparse
import os.path
import shutil
import subprocess
import urllib.request

SCRIPT_DIRECTORY = os.path.dirname(os.path.abspath(__file__))
PYZ_URL = "https://raw.githubusercontent.com/Soreepeong/XivMitmLatencyMitigator/refs/heads/main/mitigate.pyz"


def __main__() -> int:
    print("This deprecated script is an alias to mitigate.pyz. Consider moving to that instead.")
    parser = argparse.ArgumentParser("XivMitmLatencyMitigator: https://github.com/Soreepeong/XivMitmLatencyMitigator")
    parser.add_argument("-r", "--region", action="append", dest="region", default=[], choices=("JP", "CN", "KR"))
    parser.add_argument("-e", "--extra-delay", action="store", dest="extra_delay", default=0.075, type=float)
    parser.add_argument("-m", "--measure-ping", action="store_true", dest="measure_ping", default=False)
    parser.add_argument("-u", "--update-opcodes", action="store_true", dest="update_opcodes", default=False)
    parser.add_argument("-j", "--json-path", action="store", dest="json_path", default=None)
    parser.add_argument("-x", "--exe", action="append", dest="exe_url", default=[])
    parser.add_argument("-n", "--nftables", action="store_true", dest="nftables", default=False)
    parser.add_argument("--firehose", action="store", dest="firehose", default=None)
    parser.add_argument("--no-sysctl", action="store_false", dest="write_sysctl", default=True)

    args = parser.parse_args()

    pyz_path = os.path.join(SCRIPT_DIRECTORY, "mitigate.pyz")
    if not os.path.exists(pyz_path):
        with urllib.request.urlopen(PYZ_URL) as src, open(pyz_path + ".tmp", "wb") as dst:
            shutil.copyfileobj(src, dst)
        os.rename(pyz_path + ".tmp", pyz_path)

    args2 = [pyz_path]
    for r in args.region:
        args2.append(f"--region={r}")
    args2.append(f"--extra-delay={args.extra_delay}")
    if args.measure_ping:
        args2.append(f"--measure-ping")
    if args.update_opcodes:
        args2.append(f"--update-opcodes")
    if args.json_path:
        args2.append(f"--json-path={args.json_path}")
    for r in args.exe_url:
        args2.append(f"--exe={r}")
    if args.nftables:
        args2.append("--firewall=nftables")
    else:
        args2.append("--firewall=iptables")
    if not args.write_sysctl:
        args2.append("--write-sysctl")
    if args.firehose:
        print("firehose is not supported")
    return subprocess.call(args2)


if __name__ == "__main__":
    exit(__main__())
