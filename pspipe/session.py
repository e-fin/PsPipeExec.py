"""Layer 3 protocol driver (instrumented).

Fixes over the previous version, based on the wire trace:
  * A pipeline is registered with a `<Command PSGuid=...>` packet and its
    `<CommandAck>` awaited BEFORE sending the CreatePipeline data. Without this
    the server acks the bytes but never starts a pipeline.
  * `<Data>` packets carrying a pipeline message now ride on that pipeline's
    PSGuid channel (not the empty pool GUID).
  * The client now sends `<DataAck>` for each server `<Data>` packet, which the
    pipeline-output path expects.

Set PSPIPE_DEBUG=1 to trace bytes and message types.
"""

from __future__ import annotations

import os
import sys
import threading
import time
import traceback
import uuid
from typing import Callable, Optional, Protocol

from pypsrp.complex_objects import (
    ApartmentState,
    Command,
    HostInfo,
    Pipeline,
    PipelineResultTypes,
    PSThreadOptions,
    RemoteStreamOptions,
)
from pypsrp.messages import (
    CreatePipeline,
    Destination,
    InitRunspacePool,
    Message,
    MessageType,
    SessionCapability,
)
from pypsrp.serializer import Serializer

from .framing import (
    EMPTY_GUID,
    Defragmenter,
    OOPPacket,
    PacketReader,
    fragment_message,
    parse_fragment,
)

# Debug tracing can be enabled two ways:
#   * environment variable PSPIPE_DEBUG=1 (default at import time), or
#   * calling set_debug(True) — e.g. from cli.py's --debug flag.
_DEBUG = os.environ.get("PSPIPE_DEBUG", "") not in ("", "0", "false", "False")
_MT_NAMES = {v: k for k, v in vars(MessageType).items() if k.isupper()}


def set_debug(enabled: bool) -> None:
    """Turn wire tracing on or off at runtime (used by the --debug CLI flag)."""
    global _DEBUG
    _DEBUG = bool(enabled)


def debug_enabled() -> bool:
    return _DEBUG


def _dbg(msg: str) -> None:
    if _DEBUG:
        print(f"[dbg] {msg}", file=sys.stderr, flush=True)


class ByteTransport(Protocol):
    def write(self, data: bytes) -> int: ...
    def read(self, max_bytes: int = 65536) -> bytes: ...


class PSRPSession:
    def __init__(
        self,
        transport: ByteTransport,
        on_output: Optional[Callable[[str], None]] = None,
        on_error: Optional[Callable[[str], None]] = None,
    ):
        self.transport = transport
        self.on_output = on_output or (lambda s: print(s, end="" if s.endswith("\n") else "\n"))
        self.on_error = on_error or (lambda s: print(f"[error] {s}"))

        self.serializer = Serializer()
        self.pool_id = str(uuid.uuid4())
        self._object_id = 0
        self._defrag = Defragmenter()
        self._reader = PacketReader()

        self._reader_thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._pool_open = threading.Event()
        self._pipeline_done = threading.Event()
        self._command_ack = threading.Event()

    # -- low-level packet send ------------------------------------------------

    def _next_object_id(self) -> int:
        self._object_id += 1
        return self._object_id

    def _send_oop(self, pkt: OOPPacket) -> None:
        wire = pkt.pack()
        self.transport.write(wire)
        _dbg(f"  sent <{pkt.tag}> ps_guid={pkt.ps_guid[:8]} ({len(wire)} bytes)")

    def _send_message(self, message_type: int, pid: Optional[str], data_obj) -> None:
        """Serialize a PSRP message and send it as Data packet(s).

        Pool-level messages (pid=None) go on the empty-GUID channel; pipeline
        messages ride on the pipeline's own PSGuid.
        """
        msg = Message(Destination.SERVER, self.pool_id, pid, data_obj, self.serializer)
        packed = msg.pack()
        channel = pid if pid is not None else EMPTY_GUID
        _dbg(f"send {_MT_NAMES.get(message_type, hex(message_type))} "
             f"({len(packed)} bytes, channel={channel[:8]})")
        for frag in fragment_message(self._next_object_id(), packed):
            self._send_oop(OOPPacket(tag="Data", ps_guid=channel,
                                     stream="Default", payload=frag.pack()))

    # -- handshake / pool -----------------------------------------------------

    def open(self, timeout: float = 10.0) -> None:
        self._start_reader()
        self._send_message(
            MessageType.SESSION_CAPABILITY, None,
            SessionCapability(protocol_version="2.3", ps_version="2.0",
                              serialization_version="1.1.0.1"),
        )
        self._send_message(
            MessageType.INIT_RUNSPACEPOOL, None,
            InitRunspacePool(
                min_runspaces=1, max_runspaces=1,
                thread_options=PSThreadOptions(value=0),
                apartment_state=ApartmentState(value=2),
                host_info=HostInfo(), application_arguments={},
            ),
        )
        if not self._pool_open.wait(timeout):
            self.on_error("runspace pool did not report Opened within timeout; continuing")

    # -- command execution ----------------------------------------------------

    def run_command(self, command: str, wait: bool = True, timeout: float = 30.0) -> str:
        pid = str(uuid.uuid4())
        self._pipeline_done.clear()
        self._command_ack.clear()

        # 1) register the pipeline with a Command packet and await CommandAck.
        _dbg(f"registering pipeline {pid[:8]} via <Command>")
        self._send_oop(OOPPacket(tag="Command", ps_guid=pid))
        if not self._command_ack.wait(10):
            self.on_error("no CommandAck received; sending pipeline data anyway")

        # 2) send the CreatePipeline message on the pipeline's own channel.
        pipeline = Pipeline(
            is_nested=False,
            cmds=[_build_command(command)],  # pypsrp Pipeline reads 'cmds'
            history=None,
            redirect_err_to_out=True,
        )
        self._send_message(
            MessageType.CREATE_PIPELINE, pid,
            CreatePipeline(
                no_input=True,
                apartment_state=ApartmentState(value=2),
                remote_stream_options=RemoteStreamOptions(value=0),
                add_to_history=True, host_info=HostInfo(),
                pipeline=pipeline, is_nested=False,
            ),
        )
        if wait:
            if not self._pipeline_done.wait(timeout):
                self.on_error(f"pipeline did not complete within {timeout:.0f}s")
        return ""

    # -- reader loop ----------------------------------------------------------

    def _start_reader(self) -> None:
        self._reader_thread = threading.Thread(target=self._read_loop, daemon=True)
        self._reader_thread.start()

    def _read_loop(self) -> None:
        _dbg("reader thread started")
        while not self._stop.is_set():
            try:
                data = self.transport.read(65536)
            except Exception as exc:  # noqa: BLE001
                _dbg(f"transport.read raised: {exc!r}")
                time.sleep(0.05)
                continue
            if not data:
                time.sleep(0.02)
                continue
            _dbg(f"read {len(data)} bytes from pipe")
            try:
                packets = self._reader.feed(data)
            except Exception as exc:  # noqa: BLE001
                _dbg(f"packet framing error: {exc!r}")
                continue
            for pkt in packets:
                try:
                    self._handle_packet(pkt)
                except Exception as exc:  # noqa: BLE001
                    _dbg(f"handle_packet error on <{pkt.tag}>: {exc!r}")
                    if _DEBUG:
                        traceback.print_exc()
        _dbg("reader thread exiting")

    def _handle_packet(self, pkt: OOPPacket) -> None:
        _dbg(f"recv packet <{pkt.tag}> ps_guid={pkt.ps_guid[:8]} payload={len(pkt.payload)}")
        tag = pkt.tag
        if tag == "CommandAck":
            self._command_ack.set()
            return
        if tag in ("DataAck", "SignalAck", "CloseAck"):
            return
        if tag != "Data":
            return

        # Acknowledge every server Data packet on the same channel.
        try:
            self._send_oop(OOPPacket(tag="DataAck", ps_guid=pkt.ps_guid))
        except Exception as exc:  # noqa: BLE001
            _dbg(f"failed to send DataAck: {exc!r}")

        frag = parse_fragment(pkt.payload)
        full = self._defrag.push(frag)
        if full is None:
            _dbg(f"  fragment obj {frag.object_id} id {frag.fragment_id} "
                 f"start={frag.start} end={frag.end} (buffering)")
            return
        mt_int = int.from_bytes(full[4:8], "little")
        _dbg(f"  complete message: {_MT_NAMES.get(mt_int, hex(mt_int))} ({len(full)} bytes)")
        try:
            message = Message.unpack(full, self.serializer)
        except Exception as exc:  # noqa: BLE001
            _dbg(f"  unpack failed ({exc!r}); acting on header type only")
            self._handle_by_type(mt_int, None)
            return
        self._handle_by_type(message.message_type, message)

    def _handle_by_type(self, mt: int, message) -> None:
        if mt == MessageType.PIPELINE_OUTPUT:
            if message is not None:
                self.on_output(_stringify(message.data))
        elif mt == MessageType.ERROR_RECORD:
            self.on_error(_stringify(message.data) if message is not None
                          else "(error record; body not deserialized)")
        elif mt == MessageType.PIPELINE_STATE:
            state = getattr(getattr(message, "data", None), "state", None)
            _dbg(f"  pipeline state = {state}")
            if state in (4, 5, 6):  # Completed / Failed / Stopped
                self._pipeline_done.set()
        elif mt == MessageType.RUNSPACEPOOL_STATE:
            state = getattr(getattr(message, "data", None), "state", None)
            _dbg(f"  runspacepool state = {state}")
            if state == 2:  # Opened
                self._pool_open.set()
        # host calls / private data / key exchange: accepted, not acted upon.

    def close(self) -> None:
        self._stop.set()
        if self._reader_thread:
            self._reader_thread.join(timeout=1.0)


def _build_command(command: str, is_script: bool = True) -> Command:
    none = lambda: PipelineResultTypes(value=PipelineResultTypes.NONE)
    return Command(
        cmd=command, is_script=is_script, use_local_scope=None,
        merge_my_result=none(), merge_to_result=none(), merge_previous=none(),
        merge_error=none(), merge_warning=none(), merge_verbose=none(),
        merge_debug=none(), merge_information=none(),
        args=[], end_of_statement=True,
    )


def _stringify(data) -> str:
    if data is None:
        return ""
    inner = getattr(data, "data", data)
    for attr in ("string", "text"):
        val = getattr(inner, attr, None)
        if isinstance(val, str):
            return val
    return str(inner)
