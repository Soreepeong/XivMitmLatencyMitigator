#!/usr/bin/sudo python
import asyncio
import contextlib
import ipaddress
import logging.handlers
import os
import signal
import socket
import subprocess
import sys

from arguments import build_icmp_config, load_arguments
from bootstrap import get_listen_sockaddrs, get_setuidgid, read_ffxiv_bytes, setup_cleanup_file, \
    wait_for_child_shutdown
from connections.manager import ConnectionManager
from targets import create_getaddrinfo_with_timeout, get_definitions, parse_args_targets, parse_opcode_definitions
from utils.consts import DUMMY_NET_NAME
from utils.exceptions import SubprocessFailedError
from utils.interop.linux import setup_system_configuration
from utils.interop.oodle import OodleWithBudgetAbiThunks, test_oodle
from utils.interop.xivalex import MitigationConfig
from utils.interop.zipatch import download_exes
from utils.misc import format_addr_port, dedup_targets, generate_nat64_targets, listener_from_address


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

            try:
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

            finally:
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
