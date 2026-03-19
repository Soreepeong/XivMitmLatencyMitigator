import asyncio
import collections
import contextlib
import ctypes
import dataclasses
import ipaddress
import logging
import math
import socket
import time
import typing
import zlib

from connections.handlers.forwarding import connect_racing, _pipe
from structs.tcp_info import TcpInfo
from utils.consts import AUTO_ATTACK_DELAY
from utils.exceptions import InvalidDataException
from utils.interop.oodle import OodleInstance, OodleHelper
from utils.interop.xiv_network import (
    XivMessageHeader, XivBundleHeader, XivMessageType, XivMessageIpcHeader,
    XivMessageIpcType, XivMessageIpcActionRequestCommon, XivMitmLatencyMitigatorCustomSubtype,
    XivMessageIpcCustomOriginalWaitTime, XivMessageIpcActionEffect, XivMessageIpcActorControlSelf,
    XivMessageIpcActorControlCategory, XivMessageIpcActorControl, XivMessageIpcActorCast,
)
from utils.interop.xivalex import MitigationConfig
from utils.misc import clamp, format_addr_port
from utils.numeric_statistics_tracker import NumericStatisticsTracker

if typing.TYPE_CHECKING:
    from connections.manager import ConnectionManager


_MAX_DETECT_STREAM_TYPE_BUFFER_SIZE = 65536


@dataclasses.dataclass
class PendingAction:
    action_id: int
    sequence: int
    request_timestamp: float = dataclasses.field(default_factory=time.time)
    response_timestamp: float = 0
    original_wait_time: float = 0
    is_cast: bool = False


async def _detect_stream_type(reader: asyncio.StreamReader) -> tuple[bool, bytearray]:
    buf = bytearray()
    while len(buf) < _MAX_DETECT_STREAM_TYPE_BUFFER_SIZE:
        chunk = await reader.read(65536)
        if not chunk:
            return False, buf
        buf.extend(chunk)
        result = XivBundleHeader.is_xiv_bundle(buf)
        if result is not None:
            return result, buf
    return False, buf


async def _handle_game_direction(
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        oodle_r: OodleInstance,
        oodle_w: OodleInstance,
        message_toucher: typing.Callable[[list[tuple[XivMessageHeader, bytearray]]], None]):
    header_size = ctypes.sizeof(XivBundleHeader)
    message_header_size = ctypes.sizeof(XivMessageHeader)
    try:
        while True:
            header = XivBundleHeader.from_buffer_copy(await reader.readexactly(header_size))
            body = await reader.readexactly(header.length - header_size)

            match header.compression:
                case 0:
                    body = bytearray(body)
                case 1:
                    body = bytearray(zlib.decompress(body))
                    if len(body) != header.decoded_body_length:
                        raise InvalidDataException
                case 2:
                    body = oodle_r.decode(body, header.decoded_body_length)
                case _:
                    raise InvalidDataException

            messages: list[tuple[XivMessageHeader, bytearray]] = []
            pos = 0
            for _ in range(header.message_count):
                msg_header = XivMessageHeader.from_buffer(body, pos)
                if msg_header.length < message_header_size:
                    raise InvalidDataException
                msg_data = bytearray(body[pos + message_header_size:pos + msg_header.length])
                messages.append((msg_header, msg_data))
                pos += msg_header.length

            message_toucher(messages)

            out = bytearray()
            for msg_header, msg_data in messages:
                msg_header.length = message_header_size + len(msg_data)
                out.extend(bytes(msg_header))
                out.extend(msg_data)

            match header.compression:
                case 0:
                    pass
                case 1:
                    out = zlib.compress(out)
                case 2:
                    out = oodle_w.encode(out)
                case _:
                    raise InvalidDataException

            header.decoded_body_length = sum(ctypes.sizeof(m) + len(d) for m, d in messages)
            header.message_count = len(messages)
            header.length = header_size + len(out)

            writer.write(bytes(header))
            writer.write(out)
            await writer.drain()
    finally:
        with contextlib.suppress(Exception):
            writer.write_eof()


class ForwardingXivHandler:
    def __init__(self, conn_id: int, cm: "ConnectionManager", xivalex: MitigationConfig):
        self._conn_id = conn_id
        self._cm = cm
        self._xivalex = xivalex

        self.pending_actions = collections.deque[PendingAction]()
        self.last_animation_lock_ends_at = 0.
        self.last_successful_request = PendingAction(0, 0)
        self.latency_application = NumericStatisticsTracker(10)
        self.latency_upstream = NumericStatisticsTracker(10)
        self.latency_downstream = NumericStatisticsTracker(10)
        self.latency_exaggeration = NumericStatisticsTracker(10, 30.)

        self._down_sock: socket.socket | None = None
        self._up_sock: socket.socket | None = None

    async def handle(self,
                     down_reader: asyncio.StreamReader, down_writer: asyncio.StreamWriter,
                     destination: tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int],
                     interfaces: list[str]):
        iface, up_sock = await connect_racing(destination, interfaces)
        logging.info(f"[{self._conn_id:>4}] Connected via {iface} from {format_addr_port(*up_sock.getsockname())}")
        up_reader, up_writer = await asyncio.open_connection(sock=up_sock)
        self._down_sock = down_writer.get_extra_info('socket')
        self._up_sock = up_sock

        try:
            with self._cm.track_sockets(self._down_sock, up_sock):
                async with asyncio.TaskGroup() as tg:
                    tg.create_task(self._handle_direction(
                        down_reader, up_writer, self._touch_from_downstream, "down"))
                    tg.create_task(self._handle_direction(
                        up_reader, down_writer, self._touch_from_upstream, "up"))
        finally:
            up_writer.close()
            with contextlib.suppress(Exception):
                await up_writer.wait_closed()

    async def _handle_direction(self,
                                reader: asyncio.StreamReader,
                                writer: asyncio.StreamWriter,
                                toucher: typing.Callable,
                                label: str):
        is_game, prefix = await _detect_stream_type(reader)
        reader.feed_data(prefix)
        if is_game:
            logging.info(f"[{self._conn_id:>4}]:{label} is a game connection")
            oodle_r = OodleHelper.create(True)
            oodle_w = OodleHelper.create(True)
            await _handle_game_direction(reader, writer, oodle_r, oodle_w, toucher)
        else:
            logging.info(f"[{self._conn_id:>4}]:{label} is not a game connection")
            await _pipe(reader, writer)

    def _touch_from_downstream(self, messages: list[tuple[XivMessageHeader, bytearray]]):
        for message_header, message_data in messages:
            if message_header.type != XivMessageType.Ipc:
                continue

            ipc = XivMessageIpcHeader.from_buffer(message_data)
            if ipc.type != XivMessageIpcType.UnknownButInterested:
                continue

            if ipc.subtype not in (
                    self._xivalex.definitions[0].C2S_ActionRequest,
                    self._xivalex.definitions[0].C2S_ActionRequestGroundTargeted
            ):
                continue

            request = XivMessageIpcActionRequestCommon.from_buffer(message_data, ctypes.sizeof(ipc))
            self.pending_actions.append(PendingAction(request.action_id, request.sequence))

            if self.pending_actions[-1].request_timestamp > self.last_animation_lock_ends_at:
                if len(self.pending_actions) == 1:
                    self.last_animation_lock_ends_at = self.pending_actions[-1].request_timestamp

            logging.info(f"C2S_ActionRequest: actionId={request.action_id:04x} sequence={request.sequence:04x}")

    def _touch_from_upstream(self, messages: list[tuple[XivMessageHeader, bytearray]]):
        message_insertions: list[tuple[int, XivMessageHeader, bytearray]] = []
        wait_time_dict: dict[int, float] = {}
        for i, (message_header, message_data) in enumerate(messages):
            if not message_header.type == XivMessageType.Ipc:
                continue
            if message_header.source_actor != message_header.target_actor:
                continue
            try:
                ipc = XivMessageIpcHeader.from_buffer(message_data)
                if (ipc.type == XivMessageIpcType.XivMitmLatencyMitigatorCustom
                        and ipc.subtype == XivMitmLatencyMitigatorCustomSubtype.OriginalWaitTime):
                    data = XivMessageIpcCustomOriginalWaitTime.from_buffer(message_data, ctypes.sizeof(ipc))
                    wait_time_dict[data.source_sequence] = data.original_wait_time
                if ipc.type != XivMessageIpcType.UnknownButInterested:
                    continue
                if self._xivalex.definitions[0].is_action_effect(int(ipc.subtype)):
                    effect = XivMessageIpcActionEffect.from_buffer(message_data, ctypes.sizeof(ipc))
                    original_wait_time = wait_time_dict.get(effect.source_sequence, effect.animation_lock_duration)
                    wait_time = original_wait_time
                    now = time.time()
                    extra_message = ""

                    if effect.source_sequence == 0:
                        if (not self.last_successful_request.is_cast
                                and self.last_successful_request.sequence
                                and self.last_animation_lock_ends_at > now):
                            self.last_successful_request.action_id = effect.action_id
                            self.last_successful_request.sequence = 0
                            self.last_animation_lock_ends_at += (
                                    (original_wait_time + now)
                                    - (self.last_successful_request.original_wait_time
                                       + self.last_successful_request.response_timestamp)
                            )
                            self.last_animation_lock_ends_at = max(self.last_animation_lock_ends_at,
                                                                   now + AUTO_ATTACK_DELAY)
                            wait_time = self.last_animation_lock_ends_at - now
                        extra_message += " serverOriginated"
                    else:
                        while self.pending_actions and self.pending_actions[0].sequence != effect.source_sequence:
                            item = self.pending_actions.popleft()
                            logging.info(f"\t┎ ActionRequest ignored for processing: actionId={item.action_id:04x} "
                                         f"sequence={item.sequence:04x}")

                        if self.pending_actions:
                            self.last_successful_request = self.pending_actions.popleft()
                            self.last_successful_request.response_timestamp = now
                            self.last_successful_request.original_wait_time = original_wait_time
                            if not self.last_successful_request.is_cast:
                                rtt = (self.last_successful_request.response_timestamp
                                       - self.last_successful_request.request_timestamp)
                                self.latency_application.add(rtt)
                                extra_message += f" rtt={rtt * 1000:.0f}ms"
                                delay, message_append = self._resolve_adjusted_extra_delay(rtt)
                                extra_message += message_append
                                self.last_animation_lock_ends_at += original_wait_time + delay
                                wait_time = self.last_animation_lock_ends_at - now

                    if math.isclose(wait_time, original_wait_time):
                        logging.info(f"S2C_ActionEffect: actionId={effect.action_id:04x} "
                                     f"sourceSequence={effect.source_sequence:04x} "
                                     f"wait={int(original_wait_time * 1000)}ms{extra_message}")
                    else:
                        logging.info(f"S2C_ActionEffect: actionId={effect.action_id:04x} "
                                     f"sourceSequence={effect.source_sequence:04x} "
                                     f"wait={int(original_wait_time * 1000)}ms->{int(wait_time * 1000)}ms"
                                     f"{extra_message}")
                        effect.animation_lock_duration = max(0., wait_time)

                        custom_message_data = bytearray(ctypes.sizeof(XivMessageIpcCustomOriginalWaitTime)
                                                        + ctypes.sizeof(XivMessageIpcHeader))
                        custom_ipc = XivMessageIpcHeader.from_buffer(custom_message_data)
                        custom_ipc.type = XivMessageIpcType.XivMitmLatencyMitigatorCustom
                        custom_ipc.subtype = XivMitmLatencyMitigatorCustomSubtype.OriginalWaitTime
                        custom_ipc.server_id = ipc.server_id
                        custom_ipc.epoch = ipc.epoch

                        custom_ipc_original_wait_time = XivMessageIpcCustomOriginalWaitTime.from_buffer(
                            custom_message_data, ctypes.sizeof(custom_ipc))
                        custom_ipc_original_wait_time.source_sequence = int(effect.source_sequence)

                        custom_message = XivMessageHeader()
                        custom_message.source_actor = message_header.source_actor
                        custom_message.target_actor = message_header.target_actor
                        custom_message.type = XivMessageType.Ipc
                        custom_message.length = sum(ctypes.sizeof(x) for x in (
                            custom_ipc_original_wait_time, custom_ipc, custom_message))

                        message_insertions.append((i, custom_message, custom_message_data))

                elif ipc.subtype == self._xivalex.definitions[0].S2C_ActorControlSelf:
                    control = XivMessageIpcActorControlSelf.from_buffer(message_data, ctypes.sizeof(ipc))
                    if control.category == XivMessageIpcActorControlCategory.Rollback:
                        action_id = control.param_3
                        source_sequence = control.param_6
                        while (self.pending_actions
                               and (
                                       (source_sequence and self.pending_actions[0].sequence != source_sequence)
                                       or (not source_sequence and self.pending_actions[0].action_id != action_id)
                               )):
                            item = self.pending_actions.popleft()
                            logging.info(f"\t┎ ActionRequest ignored for processing: actionId={item.action_id:04x} "
                                         f"sequence={item.sequence:04x}")
                        if self.pending_actions:
                            self.pending_actions.popleft()
                        logging.info(f"S2C_ActorControlSelf/ActionRejected: "
                                     f"actionId={action_id:04x} "
                                     f"sourceSequence={source_sequence:08x}")

                elif ipc.subtype == self._xivalex.definitions[0].S2C_ActorControl:
                    control = XivMessageIpcActorControl.from_buffer(message_data, ctypes.sizeof(ipc))
                    if control.category == XivMessageIpcActorControlCategory.CancelCast:
                        action_id = control.param_3
                        while self.pending_actions and self.pending_actions[0].action_id != action_id:
                            item = self.pending_actions.popleft()
                            logging.info(f"\t┎ ActionRequest ignored for processing: actionId={item.action_id:04x} "
                                         f"sequence={item.sequence:04x}")
                        if self.pending_actions:
                            self.pending_actions.popleft()
                        logging.info(f"S2C_ActorControl/CancelCast: actionId={action_id:04x}")

                elif ipc.subtype == self._xivalex.definitions[0].S2C_ActorCast:
                    cast = XivMessageIpcActorCast.from_buffer(message_data, ctypes.sizeof(ipc))
                    if self.pending_actions:
                        self.pending_actions[0].is_cast = True
                    logging.info(f"S2C_ActorCast: actionId={cast.action_id:04x} type={cast.skill_type:04x} "
                                 f"action_id_2={cast.action_id_2:04x} time={cast.cast_time:.3f} "
                                 f"target_id={cast.target_id:08x}")

            except Exception as e:
                logging.exception(f"unknown error {e} occurred in upstream handler; skipping")

        for i, message_header, message_data in reversed(message_insertions):
            messages.insert(i, (message_header, message_data))

    def _resolve_adjusted_extra_delay(self, rtt: float) -> tuple[float, str]:
        if not self._xivalex.measure_ping:
            return self._xivalex.extra_delay, ""

        extra_message = ""
        latency_downstream = TcpInfo.get_latency(self._down_sock)
        latency_upstream = TcpInfo.get_latency(self._up_sock)
        if latency_downstream is not None:
            self.latency_downstream.add(latency_downstream)
            extra_message += f" downstream={int(latency_downstream * 1000)}ms"
        if latency_upstream is not None:
            self.latency_upstream.add(latency_upstream)
            extra_message += f" upstream={int(latency_upstream * 1000)}ms"
        if latency_downstream is None or latency_upstream is None:
            return self._xivalex.extra_delay, extra_message

        latency = latency_downstream + latency_upstream
        if latency > rtt:
            self.latency_exaggeration.add(latency - rtt)

        if self.latency_exaggeration:
            exaggeration = self.latency_exaggeration.median()
            extra_message += f" latency={latency * 1000:.0f}ms->{1000 * (latency - exaggeration):.0f}ms"
            latency -= exaggeration
        else:
            extra_message += f" latency={latency * 1000:.0f}ms"

        if rtt > 100 and latency < 5:
            extra_message += " unreliableLatency"
            return self._xivalex.extra_delay, extra_message

        rtt_min = self.latency_application.min()
        rtt_mean = self.latency_application.mean()
        rtt_deviation = self.latency_application.deviation()
        latency_mean = self.latency_upstream.mean() + self.latency_downstream.mean()
        latency_deviation = self.latency_upstream.deviation() + self.latency_downstream.deviation()

        latency = clamp(latency, latency_mean - latency_deviation, latency_mean + latency_deviation)
        rtt = clamp(rtt, rtt_mean - rtt_deviation, rtt_mean + rtt_deviation)

        latency_estimate = (rtt + rtt_min + rtt_mean) / 3 - rtt_deviation
        extra_message += f" latencyEstimate={latency_estimate * 1000:.0f}ms"

        latency = max(latency_estimate, latency)
        delay = clamp(rtt - latency, 0.001, self._xivalex.extra_delay * 2)
        extra_message += f" delayAdjusted={delay * 1000:.0f}ms"
        return delay, extra_message
