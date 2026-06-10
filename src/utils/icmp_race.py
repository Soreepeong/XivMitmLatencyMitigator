import os
import sys
import socket
import struct
import time
import asyncio
import contextlib
import dataclasses
import logging
import math
import random
import re

ICMP_ECHO_REQUEST = 8
ICMP_CODE = 0


@dataclasses.dataclass
class FindBestInterfaceConfig:
    num_attempts: int = 7
    interval: tuple[float, float] | float = (0.1, 0.3)
    penalties: dict[str, float] = dataclasses.field(default_factory=dict)
    debug: bool = False
    cache_ttl: float = 30.0


def get_default_route_interfaces() -> list[str]:
    interfaces = set()
    proc_route_path = "/proc/net/route"

    if not os.path.exists(proc_route_path):
        return []

    try:
        with open(proc_route_path, "r") as f:
            lines = f.readlines()

        # Skip the header line
        for line in lines[1:]:
            parts = line.strip().split()
            if len(parts) >= 3:
                iface = parts[0]
                destination = parts[1]
                # '00000000' in the destination column means 0.0.0.0 (the default route)
                if destination == "00000000":
                    interfaces.add(iface)
    except Exception as e:
        logging.error(f"Could not read routing table: {e}")

    return list(interfaces)


def _calculate_checksum(source_string: bytes) -> int:
    count_to = (len(source_string) // 2) * 2
    count = 0
    sum_val = 0
    while count < count_to:
        this_val = source_string[count + 1] * 256 + source_string[count]
        sum_val = (sum_val + this_val) & 0xffffffff
        count += 2
    if count_to < len(source_string):
        sum_val = (sum_val + source_string[len(source_string) - 1]) & 0xffffffff
    sum_val = (sum_val >> 16) + (sum_val & 0xffff)
    sum_val += (sum_val >> 16)
    return (~sum_val & 0xffff) >> 8 | ((~sum_val & 0xffff) << 8 & 0xff00)


def _create_packet(packet_id: int, seq_number: int) -> bytes:
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, ICMP_CODE, 0, packet_id, seq_number)
    payload = struct.pack("d", time.time())
    checksum = _calculate_checksum(header + payload)
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, ICMP_CODE, socket.htons(checksum), packet_id, seq_number)
    return header + payload


async def _send_and_listen(
        sock: socket.socket,
        interface: str,
        destination: str,
        packet_id: int,
        num_attempts: int,
        interval: tuple[float, float] | float,
        debug: bool
) -> list:
    loop = asyncio.get_running_loop()
    delays = []
    tx_times = {}
    expected_seqs = set()
    warmed_up = asyncio.Event()

    # Keep base_seq low enough that base_seq + num_attempts (the warm-up sequence) still fits in the
    # signed 16-bit ICMP sequence field.
    base_seq = hash(interface) % (0x8000 - (num_attempts + 1))
    warmup_seq = base_seq + num_attempts

    async def listen_loop():
        try:
            while len(delays) < num_attempts:
                packet = await loop.sock_recv(sock, 1024)
                recv_time = time.time()

                if len(packet) < 8:
                    continue

                # Datagram ICMP sockets deliver the payload starting at the ICMP header (no IP
                # header) and the kernel owns the echo id, only delivering replies belonging to
                # this socket; match on the sequence number alone.
                type_val, code, _, _, sequence = struct.unpack("bbHHh", packet[:8])

                if type_val != 0:
                    continue
                if sequence == warmup_seq:
                    warmed_up.set()  # tunnel/path is up; the warm-up reply is not measured
                elif sequence in expected_seqs:
                    delay = (recv_time - tx_times[sequence]) * 1000
                    delays.append(delay)
                    if debug:
                        logging.info(f"Interface: {interface} | Seq: #{sequence} | Time: {delay:.2f} ms")
        except asyncio.CancelledError:
            pass

    listener_task = asyncio.create_task(listen_loop())

    try:
        await asyncio.sleep(random.uniform(0.001, 0.05))

        # Warm-up: a first probe to trigger any one-time, on-demand path setup (notably a WireGuard
        # handshake) whose latency would otherwise be charged to the first real measurement. Its
        # reply is discarded; wait briefly for it so the path is established before measuring.
        sock.sendto(_create_packet(packet_id, warmup_seq), (destination, 1))
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(warmed_up.wait(), timeout=1.0)

        for i in range(num_attempts):
            seq = base_seq + i
            expected_seqs.add(seq)
            packet = _create_packet(packet_id, seq)

            tx_times[seq] = time.time()
            sock.sendto(packet, (destination, 1))

            if i < num_attempts - 1:
                if isinstance(interval, tuple):
                    wait_time = random.uniform(interval[0], interval[1])
                else:
                    wait_time = interval
                await asyncio.sleep(wait_time)

        await asyncio.sleep(1.0)

    finally:
        listener_task.cancel()
        await asyncio.gather(listener_task, return_exceptions=True)

    return delays


async def find_best_interface(
        destination: str,
        interfaces: list[str],
        num_attempts: int = 7,
        interval: tuple[float, float] | float = (0.1, 0.3),
        penalties: dict[str, float] | None = None,
        debug: bool = False
) -> str:
    pid = os.getpid() & 0xFFFF
    sockets = {}
    tasks = {}

    if penalties is None:
        penalties = {}

    try:
        target_ip = socket.gethostbyname(destination)
    except socket.gaierror:
        raise RuntimeError(f"Could not resolve host/IP: {destination}")

    try:
        for iface in interfaces:
            # Unprivileged ICMP "ping" datagram socket. Unlike SOCK_RAW it does not require
            # CAP_NET_RAW (which is dropped along with root when serving as an unprivileged user);
            # instead the process GID must fall within net.ipv4.ping_group_range (set by
            # --write-sysctl). The kernel assigns and demultiplexes the echo id per socket.
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, iface.encode())
            sock.setblocking(False)
            sockets[iface] = sock

        if debug:
            logging.info(f"Monitoring target {destination} ({target_ip}) via {interfaces} concurrently...")
            if isinstance(interval, tuple):
                logging.info(f"Pacing randomized between {interval[0]}s and {interval[1]}s")
            else:
                logging.info(f"Pacing fixed at {interval}s")

        for iface, sock in sockets.items():
            tasks[iface] = asyncio.create_task(
                _send_and_listen(sock, iface, target_ip, pid, num_attempts, interval, debug)
            )

        results = await asyncio.gather(*tasks.values(), return_exceptions=True)

        stats = {}
        for idx, iface in enumerate(tasks.keys()):
            delays = results[idx]

            if isinstance(delays, Exception) or len(delays) < (num_attempts / 2):
                if debug:
                    logging.info(f"Interface {iface} excluded due to failures or heavy packet loss.")
                continue

            mean = sum(delays) / len(delays)
            variance = sum((x - mean) ** 2 for x in delays) / len(delays)
            std_dev = math.sqrt(variance)

            # Base calculation: Mean + 2x Jitter
            base_score = mean + (2 * std_dev)
            final_score = base_score

            # Calculate and append regular expression regex penalties
            applied_penalty = 0.0
            for pattern, penalty_value in penalties.items():
                if re.match(pattern, iface):
                    applied_penalty += penalty_value

            final_score += applied_penalty
            stats[iface] = {"score": final_score, "mean": mean, "jitter": std_dev, "penalty": applied_penalty}

            if debug:
                penalty_str = f" | Penalty: +{applied_penalty}ms" if applied_penalty > 0 else ""
                logging.info(
                    f"{iface} -> Avg: {mean:.2f}ms | Jitter: {std_dev:.2f}ms | Final Score: {final_score:.2f}{penalty_str}")

        if not stats:
            raise RuntimeError("No network interfaces produced adequate tracking metrics.")

        best_iface = min(stats, key=lambda k: stats[k]["score"])
        return best_iface

    finally:
        for sock in sockets.values():
            sock.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s\t%(levelname)s\t%(message)s")

    if os.geteuid() != 0:
        logging.warning("Not running as root; ICMP ping sockets require the current GID to be "
                        "within net.ipv4.ping_group_range (sysctl).")

    if len(sys.argv) > 1:
        target_host = sys.argv[1]
    else:
        logging.error("No target host provided.")
        sys.exit(1)

    # Define score penalties based on interface name regular expressions
    INTERFACE_PENALTIES = {
        r"^wg-.*": 5.0,  # Wireguard interfaces get +5ms artificial penalty
        r"^ppp.*": 10.0,  # Dialup/PPPoE tunnels get +10ms artificial penalty
        r"^wlan.*": 3.0,  # Wi-Fi interfaces get +3ms artificial penalty over Ethernet
    }

    logging.info("Autodetecting default route interfaces...")
    detected_interfaces = get_default_route_interfaces()

    if not detected_interfaces:
        logging.error("No interfaces with a default gateway route were discovered.")
        sys.exit(1)

    logging.info(f"Found active default route interfaces: {detected_interfaces}")
    logging.info(f"Running stability-aware network test against: {target_host}")

    try:
        best = asyncio.run(
            find_best_interface(
                destination=target_host,
                interfaces=detected_interfaces,
                num_attempts=7,
                interval=(0.1, 0.3),
                penalties=INTERFACE_PENALTIES,
                debug=True
            )
        )
        logging.info(f"Optimal interface (low jitter): {best}")
    except Exception as e:
        logging.error(f"Execution failed: {e}")
