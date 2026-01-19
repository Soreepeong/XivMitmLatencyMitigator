import ctypes
import socket


class TcpInfo(ctypes.Structure):
    """TCP_INFO struct in linux 4.2
    see /usr/include/linux/tcp.h for details"""

    __u8 = ctypes.c_uint8
    __u16 = ctypes.c_uint16
    __u32 = ctypes.c_uint32
    __u64 = ctypes.c_uint64

    _fields_ = [
        ("tcpi_state", __u8),
        ("tcpi_ca_state", __u8),
        ("tcpi_retransmits", __u8),
        ("tcpi_probes", __u8),
        ("tcpi_backoff", __u8),
        ("tcpi_options", __u8),
        ("tcpi_snd_wscale", __u8, 4), ("tcpi_rcv_wscale", __u8, 4),

        ("tcpi_rto", __u32),
        ("tcpi_ato", __u32),
        ("tcpi_snd_mss", __u32),
        ("tcpi_rcv_mss", __u32),

        ("tcpi_unacked", __u32),
        ("tcpi_sacked", __u32),
        ("tcpi_lost", __u32),
        ("tcpi_retrans", __u32),
        ("tcpi_fackets", __u32),

        # Times
        ("tcpi_last_data_sent", __u32),
        ("tcpi_last_ack_sent", __u32),
        ("tcpi_last_data_recv", __u32),
        ("tcpi_last_ack_recv", __u32),
        # Metrics
        ("tcpi_pmtu", __u32),
        ("tcpi_rcv_ssthresh", __u32),
        ("tcpi_rtt", __u32),
        ("tcpi_rttvar", __u32),
        ("tcpi_snd_ssthresh", __u32),
        ("tcpi_snd_cwnd", __u32),
        ("tcpi_advmss", __u32),
        ("tcpi_reordering", __u32),

        ("tcpi_rcv_rtt", __u32),
        ("tcpi_rcv_space", __u32),

        ("tcpi_total_retrans", __u32),

        ("tcpi_pacing_rate", __u64),
        ("tcpi_max_pacing_rate", __u64),

        ("tcpi_bytes_acked", __u64),
        ("tcpi_bytes_received", __u64),
        ("tcpi_segs_out", __u32),
        ("tcpi_segs_in", __u32),

        ("tcpi_notsent_bytes", __u32),
        ("tcpi_min_rtt", __u32),
        ("tcpi_data_segs_in", __u32),
        ("tcpi_data_segs_out", __u32),

        ("tcpi_delivery_rate", __u64),

        ("tcpi_busy_time", __u64),
        ("tcpi_rwnd_limited", __u64),
        ("tcpi_sndbuf_limited", __u64),

        ("tcpi_delivered", __u32),
        ("tcpi_delivered_ce", __u32),

        ("tcpi_bytes_sent", __u64),
        ("tcpi_bytes_retrans", __u64),
        ("tcpi_dsack_dups", __u32),
        ("tcpi_reord_seen", __u32),

        ("tcpi_rcv_ooopack", __u32),

        ("tcpi_snd_wnd", __u32),
        ("tcpi_rcv_wnd", __u32),

        ("tcpi_rehash", __u32),

        ("tcpi_total_rto", __u16),
        ("tcpi_total_rto_recoveries", __u16),
        ("tcpi_total_rto_time", __u32),
        ("tcpi_received_ce", __u32),
        ("tcpi_delivered_e1_bytes", __u32),
        ("tcpi_delivered_e0_bytes", __u32),
        ("tcpi_delivered_ce_bytes", __u32),
        ("tcpi_received_e1_bytes", __u32),
        ("tcpi_received_e0_bytes", __u32),
        ("tcpi_received_ce_bytes", __u32),
        ("tcpi_accecn_fail_mode", __u16),
        ("tcpi_accecn_opt_seen", __u16),
    ]

    del __u8, __u16, __u32, __u64

    def __repr__(self):
        keyval = ["{}={!r}".format(x[0], getattr(self, x[0]))
                  for x in self._fields_]
        fields = ", ".join(keyval)
        return "{}({})".format(self.__class__.__name__, fields)

    @classmethod
    def from_socket(cls, sock: socket.socket):
        buf = bytearray(ctypes.sizeof(TcpInfo))
        data = sock.getsockopt(socket.SOL_TCP, socket.TCP_INFO, len(buf))
        buf[:len(data)] = data
        return cls.from_buffer(buf)

    @classmethod
    def get_latency(cls, sock: socket.socket) -> float | None:
        info = cls.from_socket(sock)
        if info.tcpi_rtt:
            return info.tcpi_rtt / 1000000
        else:
            return None
