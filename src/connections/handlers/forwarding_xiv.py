import collections
import ctypes
import dataclasses
import ipaddress
import logging
import math
import selectors
import socket
import time
import typing
import zlib

from connections.handlers import ForwardingConnectionHandler
from connections.handlers.forwarding import EndpointStream
from structs.tcp_info import TcpInfo
from utils.consts import AUTO_ATTACK_DELAY
from utils.exceptions import InvalidDataException
from utils.interop.oodle import OodleInstance, OodleHelper
from utils.interop.xiv_network import XivMessageHeader, XivBundleHeader, XivMessageType, XivMessageIpcHeader, \
    XivMessageIpcType, XivMessageIpcActionRequestCommon, XivMitmLatencyMitigatorCustomSubtype, \
    XivMessageIpcCustomOriginalWaitTime, XivMessageIpcActionEffect, XivMessageIpcActorControlSelf, \
    XivMessageIpcActorControlCategory, XivMessageIpcActorControl, XivMessageIpcActorCast
from utils.interop.xivalex import MitigationConfig
from utils.misc import clamp
from utils.numeric_statistics_tracker import NumericStatisticsTracker
from utils.ring_byte_buffer import RingByteBuffer


@dataclasses.dataclass
class PendingAction:
    action_id: int
    sequence: int
    request_timestamp: float = dataclasses.field(default_factory=time.time)
    response_timestamp: float = 0
    original_wait_time: float = 0
    is_cast: bool = False


class XivEndpointStream(EndpointStream):
    _message_toucher: typing.Callable[[list[tuple[XivMessageHeader, bytearray]]], None] | None = None
    _buf_w: RingByteBuffer | None = None
    _oodle_r: OodleInstance | None = None
    _oodle_w: OodleInstance | None = None

    def _forward_to_initial(self, target: "XivEndpointStream"):
        # Attempt to detect if this stream is a FFXIV connection
        match XivBundleHeader.is_xiv_bundle(self._buf_r.get_read_buffer()):
            case True:
                self._oodle_r = OodleHelper.create(True)
                self._oodle_w = OodleHelper.create(True)
                self._buf_w = RingByteBuffer(XivBundleHeader.MAX_LENGTH)
                self._forward_to = self._forward_to_game
                logging.info(f"[{self}] is a game connection")

            case False:
                self._forward_to = super()._forward_to
                logging.info(f"[{self}] is not a game connection")

            case _:  # Insufficient data to determine whether it is the case
                return  # Try again when more data is received

        self._forward_to(target)

    _forward_to = _forward_to_initial

    def _forward_to_game(self, target: "XivEndpointStream"):
        assert self._message_toucher is not None

        while True:
            if self._buf_w:
                buf = self._buf_w.get_read_buffer()
                target.selector.modify(event_out=True)
                send_len = target.sock.send(buf)
                self._buf_w.commit_read(send_len)

            elif self._buf_r:
                self._buf_r.compact()
                buf = self._buf_r.get_read_buffer()

                if len(buf) < ctypes.sizeof(XivBundleHeader):
                    logging.debug(f"[{self}] waiting for bundle header ({len(buf)}/{ctypes.sizeof(XivBundleHeader)}")
                    return

                header = XivBundleHeader.from_buffer(buf)
                if len(buf) < header.length:
                    logging.debug(f"[{self}] waiting for bundle ({len(buf)}/{header.length})")
                    return

                buf = buf[ctypes.sizeof(XivBundleHeader):header.length]
                self._buf_r.commit_read(header.length)

                match header.compression:
                    case 0:
                        pass
                    case 1:
                        buf = bytearray(zlib.decompress(buf))
                        if len(buf) != header.decoded_body_length:
                            raise InvalidDataException
                    case 2:
                        buf = bytearray(self._oodle_r.decode(buf, header.decoded_body_length))
                    case _:
                        raise InvalidDataException

                messages: list[tuple[XivMessageHeader, bytearray]] = []
                for _ in range(header.message_count):
                    message_header = XivMessageHeader.from_buffer(buf)
                    if message_header.length < ctypes.sizeof(message_header):
                        raise InvalidDataException
                    message_data = buf[ctypes.sizeof(XivMessageHeader):message_header.length]
                    buf = buf[message_header.length:]
                    messages.append((message_header, message_data))

                self._message_toucher(messages)

                body = bytearray()
                for message_header, message_data in messages:
                    message_header.length = ctypes.sizeof(XivMessageHeader) + len(message_data)
                    body.extend(bytes(message_header))
                    body.extend(message_data)

                match header.compression:
                    case 0:
                        pass
                    case 1:
                        body = zlib.compress(body)
                    case 2:
                        body = self._oodle_w.encode(body)
                    case _:
                        raise InvalidDataException

                header.decoded_body_length = sum(x[0].length for x in messages)
                header.message_count = len(messages)
                header.length = ctypes.sizeof(header) + len(body)

                buf = self._buf_w.get_write_buffer()
                buf[:ctypes.sizeof(header)] = bytes(header)
                buf[ctypes.sizeof(header):header.length] = body
                self._buf_w.commit_write(header.length)

            else:
                target.selector.modify(event_out=False)
                return


class ForwardingXivConnectionHandler(ForwardingConnectionHandler, endpoint_stream_impl=XivEndpointStream):
    _down: XivEndpointStream
    _up: XivEndpointStream

    def __init__(self,
                 selector: selectors.BaseSelector,
                 conn_id: int,
                 sock: socket.socket,
                 destination: tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int],
                 upstream_interface: str | None,
                 xivalex: MitigationConfig):
        super().__init__(selector, conn_id, sock, destination, upstream_interface)
        self._xivalex = xivalex
        self._down._message_toucher = self._touch_from_downstream
        self._up._message_toucher = self._touch_from_upstream

        self.pending_actions = collections.deque[PendingAction]()

        self.last_animation_lock_ends_at = 0.
        self.last_successful_request = PendingAction(0, 0)

        self.latency_application = NumericStatisticsTracker(10)
        self.latency_upstream = NumericStatisticsTracker(10)
        self.latency_downstream = NumericStatisticsTracker(10)
        self.latency_exaggeration = NumericStatisticsTracker(10, 30.)

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

            # If somehow latest action request has been made before last animation lock end time, keep it.
            # Otherwise...
            if self.pending_actions[-1].request_timestamp > self.last_animation_lock_ends_at:

                # If there was no action queued to begin with before the current one,
                # update the base lock time to now.
                if len(self.pending_actions) == 1:
                    self.last_animation_lock_ends_at = self.pending_actions[-1].request_timestamp

            logging.info(f"C2S_ActionRequest: actionId={request.action_id:04x} sequence={request.sequence:04x}")

    def _touch_from_upstream(self, messages: list[tuple[XivMessageHeader, bytearray]]):
        message_insertions: typing.List[tuple[int, XivMessageHeader, bytearray]] = []
        wait_time_dict: typing.Dict[int, float] = {}
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
                        # Process actions originating from server.
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
                            # 100ms animation lock after cast ends stays.
                            # Modify animation lock duration for instant actions only.
                            # Since no other action is in progress right before the cast ends,
                            # we can safely replace the animation lock with the latest after-cast lock.
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
                        custom_message.length = sum(ctypes.sizeof(x) for x in (custom_ipc_original_wait_time,
                                                                               custom_ipc, custom_message))

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

                    # Mark that the last request was a cast.
                    # If it indeed is a cast, the game UI will block the user from generating additional requests,
                    # so first item is guaranteed to be the cast action.
                    if self.pending_actions:
                        self.pending_actions[0].is_cast = True

                    logging.info(f"S2C_ActorCast: actionId={cast.action_id:04x} type={cast.skill_type:04x} "
                                 f"action_id_2={cast.action_id_2:04x} time={cast.cast_time:.3f} "
                                 f"target_id={cast.target_id:08x}")

            except Exception as e:
                logging.exception(f"unknown error {e} occurred in downstream handler; skipping")
        for i, message_header, message_data in reversed(message_insertions):
            messages.insert(i, (message_header, message_data))

    def _resolve_adjusted_extra_delay(self, rtt: float) -> tuple[float, str]:
        if not self._xivalex.measure_ping:
            return self._xivalex.extra_delay, ""

        extra_message = ""
        latency_downstream = TcpInfo.get_latency(self._down.sock)
        latency_upstream = TcpInfo.get_latency(self._up.sock)
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

        # Correct latency and server response time values in case of outliers.
        latency = clamp(latency, latency_mean - latency_deviation, latency_mean + latency_deviation)
        rtt = clamp(rtt, rtt_mean - rtt_deviation, rtt_mean + rtt_deviation)

        # Estimate latency based on server response time statistics.
        latency_estimate = (rtt + rtt_min + rtt_mean) / 3 - rtt_deviation
        extra_message += f" latencyEstimate={latency_estimate * 1000:.0f}ms"

        # Correct latency value based on estimate if server response time is stable.
        latency = max(latency_estimate, latency)

        # This delay is based on server's processing time.
        # If the server is busy, everyone should feel the same effect.
        # * Only the player's ping is taken out of the equation. (- latencyAdjusted)
        # * Prevent accidentally too high ExtraDelay. (Clamp above 1ms)
        delay = clamp(rtt - latency, 0.001, self._xivalex.extra_delay * 2)
        extra_message += f" delayAdjusted={delay * 1000:.0f}ms"
        return delay, extra_message
