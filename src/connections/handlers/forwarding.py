import collections
import contextlib
import ctypes
import dataclasses
import logging
import math
import os
import selectors
import socket
import time
import typing
import zlib

from utils.exceptions import InvalidDataException
from utils.interop.oodle import OodleHelper, OodleInstance
from utils.interop.xiv_network import XivBundleHeader, XivMessageHeader, XivMessageType, XivMessageIpcHeader, \
    XivMessageIpcType, XivMessageIpcActionRequestCommon, XivMitmLatencyMitigatorCustomSubtype, \
    XivMessageIpcCustomOriginalWaitTime, XivMessageIpcActionEffect, XivMessageIpcActorControlSelf, \
    XivMessageIpcActorCast, XivMessageIpcActorControl, XivMessageIpcActorControlCategory
from utils.interop.xivalex import MitigationConfig
from utils.misc import clamp
from utils.numeric_statistics_tracker import NumericStatisticsTracker
from .base import BaseConnectionHandler
from utils.consts import BLOCKING_IO_ERRORS, AUTO_ATTACK_DELAY
from structs.tcp_info import TcpInfo
from utils.ring_byte_buffer import RingByteBuffer


@dataclasses.dataclass
class PendingAction:
    action_id: int
    sequence: int
    request_timestamp: float = dataclasses.field(default_factory=time.time)
    response_timestamp: float = 0
    original_wait_time: float = 0
    is_cast: bool = False


class ForwardingConnectionHandler(BaseConnectionHandler):
    def __init__(self,
                 conn_id: int,
                 sock: socket.socket,
                 source: tuple[str, int],
                 destination: tuple[str, int],
                 selector: selectors.BaseSelector,
                 upstream_interface: str | None,
                 xivalex: MitigationConfig | None):
        self._conn_id = conn_id
        self._selector = selector
        self._closed = False
        self._source = source
        self._destination = destination
        self._xivalex = xivalex

        if self._xivalex:
            self.pending_actions = collections.deque[PendingAction]()

            self.last_animation_lock_ends_at = 0.
            self.last_successful_request = PendingAction(0, 0)

            self.latency_application = NumericStatisticsTracker(10)
            self.latency_upstream = NumericStatisticsTracker(10)
            self.latency_downstream = NumericStatisticsTracker(10)
            self.latency_exaggeration = NumericStatisticsTracker(10, 30.)

        with contextlib.ExitStack() as self._cleanup:
            def set_closed():
                self._closed = True

            self._cleanup.callback(set_closed)

            self._cleanup.push(sock)
            sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._cleanup.push(sock2)

            self._down = ForwardingConnectionHandler.Endpoint(
                self, "down", sock, True, False, self._handle_down,
                self._touch_from_downstream if xivalex else None)
            self._up = ForwardingConnectionHandler.Endpoint(
                self, "up", sock2, True, True, self._handle_up,
                self._touch_from_upstream if xivalex else None)

            if upstream_interface is not None:
                sock2.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, f"{upstream_interface}\0".encode("utf-8"))

            try:
                self._up.sock.connect((str(self._destination[0]), self._destination[1]))
            except socket.error as e:
                if e.errno not in BLOCKING_IO_ERRORS:
                    raise

            self._cleanup = self._cleanup.pop_all()

    def __str__(self):
        return f"[{self._conn_id:>4}]"

    @property
    def sockets(self):
        yield self._down.sock
        yield self._up.sock

    @property
    def closed(self):
        return self._closed

    def close(self):
        self._cleanup.close()

    def update_statistics(self):
        self._up.update_statistics()
        self._down.update_statistics()

    def _handle_down(self, ev: int):
        if self._closed:
            return

        self._down.handle(ev, self._up)

    def _handle_up(self, ev: int):
        if self._closed:
            return

        self._up.handle(ev, self._down)

    def _handle_up_initial(self, ev: int):
        if self._closed:
            return

        if ev & selectors.EVENT_READ:
            err = self._up.sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            raise OSError(err, os.strerror(err))

        if ev & selectors.EVENT_WRITE:
            logging.info(f"{self} Connection established")
            self._down.modify_selector(True, False)
            self._up.modify_selector(True, False, self._handle_up)

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
                if self._xivalex.definitions[0].is_action_effect(ipc.subtype):
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
                                delay, message_append = self.resolve_adjusted_extra_delay(rtt)
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

    def resolve_adjusted_extra_delay(self, rtt: float) -> tuple[float, str]:
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

    class Endpoint:
        def __init__(self,
                     owner: "ForwardingConnectionHandler",
                     channel: str,
                     sock: socket.socket,
                     event_in: bool,
                     event_out: bool,
                     event_cb: typing.Callable[[int], None],
                     message_toucher: typing.Callable[[list[tuple[XivMessageHeader, bytearray]]], None]):
            self.sock = sock
            self._owner = owner
            self._buf_r = RingByteBuffer(XivBundleHeader.MAX_LENGTH)
            self._buf_w: RingByteBuffer | None = None
            self._event_in = event_in
            self._event_out = event_out
            self._event_cb = event_cb
            self._channel = channel
            self._is_xiv: bool | None = None
            self._oodle_r: OodleInstance | None = None
            self._oodle_w: OodleInstance | None = None
            self._message_toucher = message_toucher

            self._last_tcpi = TcpInfo()

            sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
            sock.setsockopt(socket.SOL_TCP, socket.TCP_QUICKACK, 1)
            sock.setblocking(False)
            self._owner._selector.register(sock, (
                    0
                    | (selectors.EVENT_READ if event_in else 0)
                    | (selectors.EVENT_WRITE if event_out else 0)
            ), (owner, event_cb))
            owner._cleanup.callback(self._owner._selector.unregister, sock)

        def __str__(self):
            return f"[{self._owner._conn_id:>4}:{self._channel}]"

        def fileno(self):
            return self.sock.fileno()

        def get_tcp_info(self):
            return TcpInfo.from_socket(self.sock)

        def update_statistics(self):
            tcpi = self.get_tcp_info()
            lost = tcpi.tcpi_lost - tcpi.tcpi_lost
            self._last_tcpi = tcpi
            if lost:
                logging.warning(
                    f"{self} Lost packets: {lost} RTT: {round(tcpi.tcpi_rtt / 1000)} var {round(tcpi.tcpi_rttvar / 1000)}")

        def handle(self, ev: int, target: "ForwardingConnectionHandler.Endpoint"):
            # self -> target
            if ev & selectors.EVENT_READ and not self._buf_r.error:
                try:
                    write_space = self._buf_r.get_write_buffer()
                    if not write_space:
                        self.modify_selector(event_in=False)
                    elif self._buf_r.commit_write(self.sock.recv_into(write_space, len(write_space))):
                        self._forward_to(target)
                    else:
                        self._buf_r.close()
                except socket.error as e:
                    if e.errno not in BLOCKING_IO_ERRORS:
                        self.modify_selector(event_in=False)
                        self._buf_r.close(e, drain=True)

                if self._buf_r.is_complete:
                    target.sock.shutdown(socket.SHUT_WR)

            # target -> self
            if ev & selectors.EVENT_WRITE:
                if target._buf_r:
                    try:
                        target._forward_to(self)
                    except socket.error as e:
                        if e.errno not in BLOCKING_IO_ERRORS:
                            target._buf_r.close(e, drain=True)
                            target.modify_selector(event_in=False)
                else:
                    self.modify_selector(event_out=False)
                    if target._buf_r.error:
                        self.sock.shutdown(socket.SHUT_WR)

            if self._buf_r.is_complete and target._buf_r.is_complete:
                raise ExceptionGroup("Both socket closed", (self._buf_r.error, target._buf_r.error))

        def modify_selector(self,
                            event_in: bool | None = None,
                            event_out: bool | None = None,
                            new_cb: typing.Callable[[int], None] = None):
            changed = False
            if event_in is not None and event_in != self._event_in:
                self._event_in = event_in
                changed = True
            if event_out is not None and event_out != self._event_out:
                self._event_out = event_out
                changed = True
            if new_cb is not None and new_cb != self._event_cb:
                self._event_cb = new_cb
                changed = True

            if changed:
                eventmask = (
                        0
                        | (selectors.EVENT_READ if self._event_in else 0)
                        | (selectors.EVENT_WRITE if self._event_out else 0)
                )
                self._owner._selector.modify(self.sock, eventmask, (self._owner, self._event_cb))

        def _forward_to(self, target: "ForwardingConnectionHandler.Endpoint"):
            while True:
                if self._buf_w:
                    buf = self._buf_w.get_read_buffer()
                    target.modify_selector(event_out=True)
                    send_len = target.sock.send(buf)
                    self._buf_w.commit_read(send_len)
                elif self._buf_r:
                    buf = self._buf_r.get_read_buffer()
                    if self._is_xiv is None:
                        check_len = min(len(XivBundleHeader.MAGIC_CONSTANT_1), len(buf))
                        if (XivBundleHeader.MAGIC_CONSTANT_1[:check_len] != buf[:check_len] and
                                XivBundleHeader.MAGIC_CONSTANT_2[:check_len] != buf[:check_len]):
                            self._is_xiv = False
                            logging.info(f"{self} is not a game connection")
                        elif check_len == len(XivBundleHeader.MAGIC_CONSTANT_1):
                            self._is_xiv = True
                            self._oodle_r = OodleHelper.create(True)
                            self._oodle_w = OodleHelper.create(True)
                            self._buf_w = RingByteBuffer(XivBundleHeader.MAX_LENGTH)
                            logging.info(f"{self} is a game connection")
                        else:
                            return

                    if self._is_xiv:
                        if not self._handle_xiv():
                            target.modify_selector(event_out=False)
                            return
                    else:
                        target.modify_selector(event_out=True)
                        send_len = target.sock.send(buf)
                        self._buf_r.commit_read(send_len)
                else:
                    return

        def _handle_xiv(self):
            self._buf_r.compact()
            buf = self._buf_r.get_read_buffer()

            if len(buf) < ctypes.sizeof(XivBundleHeader):
                print(f"{self} waiting for bundle header ({len(buf)}/{ctypes.sizeof(XivBundleHeader)}")
                return False

            header = XivBundleHeader.from_buffer(buf)
            if len(buf) < header.length:
                print(f"{self} waiting for bundle ({len(buf)}/{header.length})")
                return False

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

            return True
