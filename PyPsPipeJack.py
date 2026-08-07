#!/usr/bin/env python3
"""CLI for connecting to a Windows PSHost named pipe over SMB and running
PowerShell commands through PSRP.

Authenticates as the supplied account. If the target pipe's DACL doesn't grant
that account access, open fails — this tool does not work around that.

Examples
--------
Enumerate PSHost pipes on the target:
    python cli.py --host 10.0.0.5 -u alice -p '...' --list

Connect to a specific pipe and get an interactive prompt:
    python cli.py --host 10.0.0.5 -u alice -p '...' \\
        --pipe 'PSHost.<ts>.<pid>.DefaultAppDomain.powershell'

Kerberos instead of NTLM:
    python cli.py --host host.lab.local -u alice -p '...' \\
        -d LAB --kerberos --list

Blank password (e.g. accounts configured without one) and full tracing:
    python cli.py --host 10.0.0.5 -u alice --no-pass --debug --list

Short flags: -u/--user, -p/--password, -d/--domain.
"""

from __future__ import annotations

import argparse
import sys
import time

from pspipe.transport import AuthConfig, PipeConn
from pspipe.session import PSRPSession, set_debug


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="PSRP-over-SMB-named-pipe client (authorized research use)")
    p.add_argument("--host", required=True, help="target Windows host")
    p.add_argument("-u", "--user", required=True, help="username to authenticate as")

    # Password: either supply one, or use --no-pass for an explicit blank
    # password. They are mutually exclusive so the two can't disagree.
    pw = p.add_mutually_exclusive_group()
    pw.add_argument("-p", "--password", default=None, help="password")
    pw.add_argument("--no-pass", action="store_true",
                    help="authenticate with a blank password")

    p.add_argument("-d", "--domain", default="", help="domain (blank for local account)")
    p.add_argument("--port", type=int, default=445)
    p.add_argument("--kerberos", action="store_true", help="use Kerberos instead of NTLM")
    p.add_argument("--aes-key", default="", help="Kerberos AES key (optional)")
    p.add_argument("--kdc-host", default=None, help="KDC host for Kerberos (optional)")

    p.add_argument("--debug", action="store_true",
                   help="print wire tracing to stderr (same as PSPIPE_DEBUG=1)")

    p.add_argument("--list", action="store_true", help="list PSHost pipes and exit")
    p.add_argument("--pipe", default="", help="full pipe name under IPC$ to connect to")
    p.add_argument("--command", default="", help="run one command and exit (non-interactive)")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    # --debug turns on the same wire tracing as PSPIPE_DEBUG=1, set before any
    # session work so the handshake is traced too. It also raises impacket's
    # own logging to DEBUG so the SMB-level exchange is visible.
    if args.debug:
        set_debug(True)
        import logging
        logging.basicConfig(
            level=logging.DEBUG,
            format="%(asctime)s [impacket] %(levelname)s %(message)s",
            stream=sys.stderr,
        )
        # impacket logs under the root logger; make sure it isn't filtered.
        logging.getLogger("impacket").setLevel(logging.DEBUG)

    # Resolve the password: --no-pass means an explicit empty password; if
    # neither --password nor --no-pass was given, default to empty as before.
    password = "" if args.no_pass else (args.password or "")

    cfg = AuthConfig(
        host=args.host,
        username=args.user,
        password=password,
        domain=args.domain,
        port=args.port,
        use_kerberos=args.kerberos,
        aes_key=args.aes_key,
        kdc_host=args.kdc_host,
    )

    conn = PipeConn(cfg)
    try:
        conn.connect()
    except Exception as exc:  # noqa: BLE001
        print(f"[!] SMB connect/auth failed: {exc}", file=sys.stderr)
        return 1

    try:
        if args.list:
            try:
                names = conn.list_pipes("PSHost")
            except Exception as exc:  # noqa: BLE001
                print(f"[!] listing IPC$ failed (may be restricted): {exc}", file=sys.stderr)
                return 1
            if not names:
                print("No PSHost pipes visible (none running, or listing restricted).")
                return 0
            print("PSHost pipes on target:")
            for n in names:
                print("  ", n)
            return 0

        if not args.pipe:
            print("[!] --pipe is required unless --list is used", file=sys.stderr)
            return 2

        try:
            conn.open_pipe(args.pipe)
        except Exception as exc:  # noqa: BLE001
            # Layer 2: an access-denied here means the pipe DACL didn't grant
            # your account access. That's expected and not worked around.
            print(f"[!] opening pipe failed: {exc}", file=sys.stderr)
            return 1

        session = PSRPSession(conn)
        session.open()

        if args.command:
            session.run_command(args.command, wait=True)
            time.sleep(0.3)
            session.close()
            return 0

        # interactive REPL
        print("Connected. Enter PowerShell commands; 'exit' to quit.")
        try:
            while True:
                try:
                    line = input("PS> ").strip()
                except EOFError:
                    break
                if line in ("exit", "quit"):
                    break
                if line:
                    session.run_command(line, wait=True, timeout=30.0)
        finally:
            session.close()
        return 0
    finally:
        conn.close()


if __name__ == "__main__":
    raise SystemExit(main())
