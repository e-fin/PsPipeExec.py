"""pspipe — PSRP client over an SMB named pipe (Windows PSHost pipes).

Scope: authenticates as yourself (NTLM/Kerberos), no DACL bypass, no
pass-the-hash. For authorized research on hosts you control.
"""

from .transport import AuthConfig, PipeConn
from .session import PSRPSession

__all__ = ["AuthConfig", "PipeConn", "PSRPSession"]
