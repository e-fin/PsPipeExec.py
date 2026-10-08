from __future__ import annotations

import base64
import struct
from dataclasses import dataclass
from typing import Dict, List, Optional
from xml.etree import ElementTree as ET

EMPTY_GUID = "00000000-0000-0000-0000-000000000000"

_FRAG_START = 0x1
_FRAG_END = 0x2

# The out-of-process transport delimits packets with a newline.
_DELIM = b"\n"


# ---- Fragments ------------------------------------------------------------

@dataclass
class Fragment:
    object_id: int
    fragment_id: int
    start: bool
    end: bool
    blob: bytes

    def pack(self) -> bytes:
        # Wire format: [object_id:8][fragment_id:8][flags:1][blob_len:4][blob:N]
        flags = (_FRAG_START if self.start else 0) | (_FRAG_END if self.end else 0)
        return (
            struct.pack(">QQB", self.object_id, self.fragment_id, flags)
            + struct.pack(">I", len(self.blob))
            + self.blob
        )


def fragment_message(object_id: int, message: bytes, max_blob: int = 32768) -> List[Fragment]:
    frags: List[Fragment] = []
    if not message:
        return [Fragment(object_id, 0, True, True, b"")]
    fid = 0
    for off in range(0, len(message), max_blob):
        chunk = message[off : off + max_blob]
        frags.append(
            Fragment(
                object_id=object_id,
                fragment_id=fid,
                start=(off == 0),
                end=(off + max_blob >= len(message)),
                blob=chunk,
            )
        )
        fid += 1
    return frags


def parse_fragment(data: bytes) -> Fragment:
    if len(data) < 21:
        raise ValueError(f"fragment too short: {len(data)}")
    object_id, fragment_id, flags = struct.unpack(">QQB", data[:17])
    (blob_len,) = struct.unpack(">I", data[17:21])
    blob = data[21 : 21 + blob_len]
    if len(blob) != blob_len:
        raise ValueError("fragment blob truncated")
    return Fragment(
        object_id=object_id,
        fragment_id=fragment_id,
        start=bool(flags & _FRAG_START),
        end=bool(flags & _FRAG_END),
        blob=blob,
    )


# Drop incomplete fragment reassembly if it exceeds this to prevent unbounded memory growth.
_MAX_FRAGMENT_BUFFER = 10 * 1024 * 1024


class Defragmenter:
    """Reassembles fragments keyed by object_id until the End flag is seen."""

    def __init__(self) -> None:
        self._buffers: Dict[int, bytearray] = {}

    def push(self, frag: Fragment) -> Optional[bytes]:
        if frag.start:
            self._buffers.pop(frag.object_id, None)
        buf = self._buffers.setdefault(frag.object_id, bytearray())
        buf.extend(frag.blob)
        if len(buf) > _MAX_FRAGMENT_BUFFER:
            del self._buffers[frag.object_id]
            return None
        if frag.end:
            out = bytes(buf)
            del self._buffers[frag.object_id]
            return out
        return None


# ---- Out-of-process packets ----------------------------------------------

@dataclass
class OOPPacket:
    tag: str                       # Data, DataAck, Command, CommandAck, Close, CloseAck, Signal, SignalAck
    ps_guid: str = EMPTY_GUID
    stream: str = "Default"
    payload: bytes = b""

    def pack(self) -> bytes:
        if self.tag == "Data":
            elem = ET.Element("Data", Stream=self.stream, PSGuid=self.ps_guid)
            elem.text = base64.b64encode(self.payload).decode("ascii")
        else:
            elem = ET.Element(self.tag, PSGuid=self.ps_guid)
        return ET.tostring(elem, encoding="unicode").encode("utf-8") + _DELIM


def parse_packet(raw: bytes) -> OOPPacket:
    """Parse one packet (newline already stripped)."""
    text = raw.decode("utf-8", errors="replace").strip()
    elem = ET.fromstring(text)
    tag = elem.tag
    ps_guid = elem.attrib.get("PSGuid", EMPTY_GUID)
    stream = elem.attrib.get("Stream", "Default")
    payload = b""
    if tag == "Data" and elem.text:
        payload = base64.b64decode(elem.text)
    return OOPPacket(tag=tag, ps_guid=ps_guid, stream=stream, payload=payload)


class PacketReader:
    """Feed raw bytes from the pipe; yields complete packets on newline boundaries."""

    def __init__(self) -> None:
        self._buf = bytearray()

    def feed(self, data: bytes) -> List[OOPPacket]:
        self._buf.extend(data)
        packets: List[OOPPacket] = []
        while True:
            idx = self._buf.find(_DELIM)
            if idx < 0:
                break
            chunk = bytes(self._buf[:idx])
            del self._buf[: idx + 1]
            # tolerate CRLF and stray whitespace
            if chunk.strip():
                try:
                    packets.append(parse_packet(chunk))
                except Exception:
                    continue
        return packets
