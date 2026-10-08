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

# Map PSRP stream message type IDs to display prefixes (built via getattr
# so the tool still works if pypsrp is missing any of these constants).
_STREAM_MESSAGE_TYPES: dict[int, str] = {
    v: label
    for attr, label in (
        ("WARNING_RECORD", "WARNING"),
        ("VERBOSE_RECORD", "VERBOSE"),
        ("DEBUG_RECORD", "DEBUG"),
        ("INFORMATION_RECORD", "INFO"),
    )
    if (v := getattr(MessageType, attr, None)) is not None
}

# Reverse lookup for debug logging: message type int -> name.
_MT_NAMES = {v: k for k, v in vars(MessageType).items() if k.isupper()}


def set_debug(enabled: bool) -> None:
    """Turn wire tracing on or off at runtime (used by the --debug CLI flag)."""
    global _DEBUG
    _DEBUG = bool(enabled)


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

        # Reader parking. The reader only issues blocking reads while _reader_run
        # is set; otherwise it parks (announcing via _reader_idle) without any
        # read pending on the pipe handle. We keep it parked whenever no command
        # is in flight, so sitting idle at the prompt never leaves a pending
        # read to corrupt the next command's writes — the session then survives
        # arbitrary idle time.
        self._reader_run = threading.Event()
        self._reader_idle = threading.Event()

    # -- low-level packet send ------------------------------------------------

    def _next_object_id(self) -> int:
        self._object_id += 1
        return self._object_id

    def _send_oop(self, pkt: OOPPacket) -> None:
        wire = pkt.pack()
        self.transport.write(wire)
        _dbg(f"  sent <{pkt.tag}> ps_guid={pkt.ps_guid[:8]} ({len(wire)} bytes)")

    def _send_message(self, message_type: int, pid: Optional[str], data_obj) -> None:
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
        self._reader_activate()  # reader active during the pool handshake
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
        # Park the reader while idle at the prompt: no read pending on the handle,
        # so the session can sit idle indefinitely between commands.
        self._reader_park()

    # -- command execution ----------------------------------------------------

    def run_command(self, command: str, wait: bool = True, timeout: float = 30.0) -> None:
        pid = str(uuid.uuid4())
        self._pipeline_done.clear()

        pipeline = Pipeline(
            is_nested=False,
            cmds=[_build_command(command)],  # pypsrp Pipeline reads 'cmds'
            history=None,
            redirect_err_to_out=True,
        )

        # Wake the reader for this command. Because it was parked while idle,
        # there is no stale read pending on the handle, so the <Command> and
        # CreatePipeline writes reach the server cleanly regardless of how long
        # we were idle. We do NOT wait on CommandAck between the two sends (a
        # bare <Command> isn't acked on its own; that wait only added delay).
        _dbg(f"activating reader + creating pipeline {pid[:8]}")
        self._reader_activate()
        self._send_oop(OOPPacket(tag="Command", ps_guid=pid))
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
        try:
            if wait:
                if not self._pipeline_done.wait(timeout):
                    self.on_error(f"pipeline did not complete within {timeout:.0f}s")
        finally:
            # Park the reader again so the next idle period is safe.
            self._reader_park()

    # -- reader loop ----------------------------------------------------------

    def _start_reader(self) -> None:
        self._reader_thread = threading.Thread(target=self._read_loop, daemon=True)
        self._reader_thread.start()

    def _reader_activate(self) -> None:
        """Wake the reader so it resumes issuing reads (a command is starting)."""
        self._reader_idle.clear()
        self._reader_run.set()

    def _reader_park(self, settle: float = 3.0) -> None:
        """Park the reader and wait for it to stop reading (command finished).

        Clears _reader_run and waits (up to `settle`) for the reader to finish
        any in-flight blocking read and announce _reader_idle. After this returns
        there is no read pending on the pipe handle, so the connection can sit
        idle indefinitely without a pending read to corrupt the next write.
        """
        self._reader_idle.clear()
        self._reader_run.clear()
        self._reader_idle.wait(settle)

    def _read_loop(self) -> None:
        _dbg("reader thread started")
        while not self._stop.is_set():
            # Park while not activated: announce idle, then wait to be resumed.
            # Checked between reads, so when parked there is no read in flight.
            if not self._reader_run.is_set():
                self._reader_idle.set()
                self._reader_run.wait(timeout=1.0)
                continue
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
        if tag in ("CommandAck", "DataAck", "SignalAck", "CloseAck"):
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
        elif mt in _STREAM_MESSAGE_TYPES:
            prefix = _STREAM_MESSAGE_TYPES[mt]
            text = _stringify(message.data) if message is not None else ""
            if text:
                self.on_output(f"[{prefix}] {text}")
        elif mt == MessageType.PIPELINE_STATE:
            state = getattr(getattr(message, "data", None), "state", None)
            _dbg(f"  pipeline state = {state}")
            # PSRP PipelineState enum: 4=Completed, 5=Failed, 6=Stopped
            if state in (4, 5, 6):
                self._pipeline_done.set()
        elif mt == MessageType.RUNSPACEPOOL_STATE:
            state = getattr(getattr(message, "data", None), "state", None)
            _dbg(f"  runspacepool state = {state}")
            # RunspacePoolState enum: 2=Opened
            if state == 2:
                self._pool_open.set()
        # host calls / private data / key exchange: accepted, not acted upon.

    def close(self) -> None:
        self._stop.set()
        if self._reader_thread:
            self._reader_thread.join(timeout=1.0)


def _build_command(command: str, is_script: bool = True) -> Command:
    # PSRP returns raw .NET objects; pipe through Out-String so PowerShell's
    # formatting engine renders them as the table/list text users expect.
    # -Stream emits line-by-line instead of one blob, for incremental output.
    formatted = f"& {{\n{command}\n}} | Out-String -Stream"
    none = lambda: PipelineResultTypes(value=PipelineResultTypes.NONE)
    return Command(
        cmd=formatted, is_script=is_script, use_local_scope=None,
        merge_my_result=none(), merge_to_result=none(), merge_previous=none(),
        merge_error=none(), merge_warning=none(), merge_verbose=none(),
        merge_debug=none(), merge_information=none(),
        args=[], end_of_statement=True,
    )


def _stringify(data) -> str:
    """Extract display text from a deserialized PSRP object.

    Tries, in order: raw string, pypsrp .string/.text attrs, .NET ToString(),
    adapted property key-value pairs, and finally repr as a last resort.
    """
    if data is None:
        return ""
    if isinstance(data, str):
        return data
    inner = getattr(data, "data", data)
    if isinstance(inner, str):
        return inner
    for attr in ("string", "text"):
        val = getattr(inner, attr, None)
        if isinstance(val, str):
            return val
    ts = getattr(inner, "to_string", None)
    if isinstance(ts, str) and ts:
        return ts
    props = getattr(inner, "adapted_properties", None)
    if props:
        return "  ".join(f"{k}: {v}" for k, v in props.items())
    return str(inner)
