"""Layer 1: SMB2 transport + named-pipe I/O over IPC$ using impacket.

Auth is ordinary NTLM or Kerberos as *yourself*. This module does not attempt
to bypass a pipe's DACL or impersonate another identity. If the target pipe's
security descriptor doesn't grant your account access, openFile raises, and that
is the access check working as intended.

Thread-safety note
------------------
impacket's SMBConnection is NOT safe to use from multiple threads: two threads
touching the same socket interleave each other's SMB responses and both stall
(you see a NetBIOS timeout). The PSRP session runs a background reader thread
while the main thread writes, so every SMB operation here is serialized behind
one lock. Reads use a short timeout so a no-data poll returns immediately and
never holds the lock while the writer is waiting.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import List, Optional

from impacket.smbconnection import SMBConnection
from impacket.nmb import NetBIOSTimeout
from impacket.smbconnection import SessionError


@dataclass
class AuthConfig:
    host: str
    username: str
    password: str = ""
    domain: str = ""
    port: int = 445
    use_kerberos: bool = False
    aes_key: str = ""
    kdc_host: Optional[str] = None
    # Timeouts (seconds). Reads are short so polling doesn't block the socket;
    # writes/handshake get a longer budget.
    read_timeout: int = 2
    op_timeout: int = 30


class PipeConn:
    """An authenticated SMB session with one open named-pipe handle under IPC$."""

    IPC = "IPC$"

    def __init__(self, cfg: AuthConfig):
        self.cfg = cfg
        self._smb: Optional[SMBConnection] = None
        self._tree_id: Optional[int] = None
        self._file_id = None
        self._pipe_name: Optional[str] = None
        # One lock guards ALL access to the SMBConnection.
        self._lock = threading.Lock()

    # -- connection lifecycle -------------------------------------------------

    def connect(self) -> "PipeConn":
        smb = SMBConnection(
            remoteName=self.cfg.host,
            remoteHost=self.cfg.host,
            sess_port=self.cfg.port,
        )
        smb.setTimeout(self.cfg.op_timeout)
        if self.cfg.use_kerberos:
            smb.kerberosLogin(
                user=self.cfg.username,
                password=self.cfg.password,
                domain=self.cfg.domain,
                aesKey=self.cfg.aes_key,
                kdcHost=self.cfg.kdc_host,
            )
        else:
            smb.login(
                user=self.cfg.username,
                password=self.cfg.password,
                domain=self.cfg.domain,
            )
        self._smb = smb
        self._tree_id = smb.connectTree(self.IPC)
        return self

    def list_pipes(self, prefix: str = "PSHost") -> List[str]:
        assert self._smb is not None, "connect() first"
        results: List[str] = []
        with self._lock:
            self._smb.setTimeout(self.cfg.op_timeout)
            entries = self._smb.listPath(self.IPC, "*")
        for entry in entries:
            name = entry.get_longname()
            if name in (".", ".."):
                continue
            if not prefix or name.lower().startswith(prefix.lower()):
                results.append(name)
        return results

    def open_pipe(self, pipe_name: str, wait: bool = True, wait_timeout: int = 5):
        assert self._smb is not None and self._tree_id is not None, "connect() first"
        with self._lock:
            self._smb.setTimeout(self.cfg.op_timeout)
            if wait:
                try:
                    self._smb.waitNamedPipe(self._tree_id, pipe_name, timeout=wait_timeout)
                except Exception:
                    pass
            self._file_id = self._smb.openFile(
                self._tree_id,
                pipe_name,
                desiredAccess=0x0012019F,  # generic read/write/append + std rights
                shareMode=0x7,             # share read/write/delete
                creationOption=0x40,       # non-directory
                creationDisposition=0x1,   # FILE_OPEN (must already exist)
            )
        self._pipe_name = pipe_name
        return self

    # -- byte-mode I/O (all serialized) --------------------------------------

    def write(self, data: bytes) -> int:
        assert self._smb is not None and self._file_id is not None, "open_pipe() first"
        with self._lock:
            self._smb.setTimeout(self.cfg.op_timeout)
            self._smb.writeFile(self._tree_id, self._file_id, data)
        return len(data)

    def read(self, max_bytes: int = 65536) -> bytes:
        """Poll the pipe for available bytes.

        Uses a short timeout so that when the pipe has nothing pending, the SMB2
        READ returns/raises quickly instead of blocking the shared socket. A
        timeout or empty read is reported as b"" (no data yet), not an error.
        """
        assert self._smb is not None and self._file_id is not None, "open_pipe() first"
        with self._lock:
            self._smb.setTimeout(self.cfg.read_timeout)
            try:
                return self._smb.readFile(
                    self._tree_id, self._file_id,
                    bytesToRead=max_bytes, singleCall=True,
                )
            except NetBIOSTimeout:
                return b""
            except SessionError:
                # e.g. STATUS_PIPE_EMPTY / pending — treat as no data this poll.
                return b""
            except Exception:
                return b""

    def close(self) -> None:
        if self._smb is None:
            return
        with self._lock:
            try:
                if self._file_id is not None:
                    self._smb.setTimeout(self.cfg.read_timeout)
                    self._smb.closeFile(self._tree_id, self._file_id)
            except Exception:
                pass
            try:
                self._smb.disconnectTree(self._tree_id)
            except Exception:
                pass
            try:
                self._smb.close()
            except Exception:
                pass
            self._smb = None

    def __enter__(self):
        return self.connect()

    def __exit__(self, *exc):
        self.close()
