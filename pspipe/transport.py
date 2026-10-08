from __future__ import annotations

import os
import threading
from dataclasses import dataclass
from typing import List, Optional

from impacket.smbconnection import SMBConnection
from impacket.nmb import NetBIOSTimeout
from impacket.smbconnection import SessionError


@dataclass
class AuthConfig:
    host: str
    username: str = ""
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
    lmhash: str = ""
    nthash: str = ""


class PipeConn:
    """An authenticated SMB session with one open named-pipe handle under IPC$."""

    IPC = "IPC$"

    def __init__(self, cfg: AuthConfig):
        self.cfg = cfg
        self._smb: Optional[SMBConnection] = None
        self._tree_id: Optional[int] = None
        self._file_id = None
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
            # Follows the impacket -k convention: if KRB5CCNAME points at a
            # credential cache, use the ticket in it (and fill in any missing
            # username/domain from the ticket's principal); otherwise fall back
            # to the supplied username/password/aesKey.
            use_cache = bool(os.getenv("KRB5CCNAME"))
            if use_cache:
                try:
                    from impacket.krb5.ccache import CCache
                    domain, username, _tgt, _tgs = CCache.parseFile(
                        self.cfg.domain, self.cfg.username
                    )
                    if not self.cfg.domain and domain:
                        self.cfg.domain = domain
                    if not self.cfg.username and username:
                        self.cfg.username = username
                except Exception:
                    # If the cache can't be parsed, still let impacket try it.
                    pass
            smb.kerberosLogin(
                user=self.cfg.username,
                password=self.cfg.password,
                domain=self.cfg.domain,
                aesKey=self.cfg.aes_key,
                kdcHost=self.cfg.kdc_host,
                useCache=use_cache,
            )
        else:
            smb.login(
                user=self.cfg.username,
                password=self.cfg.password,
                domain=self.cfg.domain,
                lmhash=self.cfg.lmhash,
                nthash=self.cfg.nthash
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
        return self

    # -- byte-mode I/O (all serialized) --------------------------------------

    def write(self, data: bytes) -> int:
        assert self._smb is not None and self._file_id is not None, "open_pipe() first"
        with self._lock:
            self._smb.setTimeout(self.cfg.op_timeout)
            self._smb.writeFile(self._tree_id, self._file_id, data)
        return len(data)

    def read(self, max_bytes: int = 65536) -> bytes:
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

    def close(self) -> None:
        if self._smb is None:
            return
        # Teardown order: pipe handle -> IPC$ tree -> SMB session.
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
