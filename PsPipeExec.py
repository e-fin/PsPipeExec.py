#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import sys

from pspipe.transport import AuthConfig, PipeConn
from pspipe.session import PSRPSession, set_debug
from impacket.examples.utils import parse_target


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="PowerShell Named Pipe Lateral Movement Tool")
    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    
    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                                                       '(KRB5CCNAME) based on target parameters. If valid credentials '
                                                       'cannot be found, it will use the ones specified in the command '
                                                       'line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication '
                                                                            '(128 or 256 bits)')
    group = parser.add_argument_group('connection')
    
    group.add_argument('-dc-ip', action='store', metavar="ip address",
                       help='IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in '
                            'the target parameter')
    group.add_argument('-port', choices=['139', '445'], nargs='?', default='445', metavar="destination port",
                       help='Destination port to connect to SMB Server')

    group = parser.add_argument_group('PowerShell Pipes')
    group.add_argument("--list", action="store_true", help="list PSHost pipes and exit")
    group.add_argument("--pipe", default="", help="full pipe name under IPC$ to connect to")
    group.add_argument("--command", default="", help="run one command and exit (non-interactive)")
    group.add_argument("--script", default="", help="run entire PS1 file")
    group.add_argument("--no-wmi", action="store_true",
                       help="skip WMI owner lookup for pipes")

    return parser


def _is_block_complete(text: str) -> bool:
    """Check if braces are balanced outside of string literals and comments."""
    depth = 0
    in_single = False
    in_double = False
    i = 0
    while i < len(text):
        c = text[i]
        if in_single:
            # '' is the escape for a literal quote inside single-quoted strings
            if c == "'" and i + 1 < len(text) and text[i + 1] == "'":
                i += 2
                continue
            if c == "'":
                in_single = False
        elif in_double:
            # Backtick is the escape character inside double-quoted strings
            if c == "`" and i + 1 < len(text):
                i += 2
                continue
            if c == '"':
                in_double = False
        else:
            if c == "'":
                in_single = True
            elif c == '"':
                in_double = True
            elif c == '#':
                # Line comment — skip to end of line
                while i < len(text) and text[i] != '\n':
                    i += 1
                continue
            elif c == '{':
                depth += 1
            elif c == '}':
                depth -= 1
        i += 1
    return depth <= 0 and not in_single and not in_double


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    print()
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

    domain, username, password, address = parse_target(args.target)

    if domain is None:
        domain = ''
    
    # Prompt for password when no other auth method was supplied.
    needs_password = (
        password == ''
        and username != ''
        and args.hashes is None
        and not args.no_pass
        and args.aesKey is None
    )
    if needs_password:
        from getpass import getpass
        password = getpass("Password:")
    if args.hashes is not None:
        parts = args.hashes.split(':')
        if len(parts) != 2:
            print("[!] --hashes format must be LMHASH:NTHASH (use empty string for missing, e.g. :NTHASH)",
                  file=sys.stderr)
            return 1
        lmhash, nthash = parts
    else:
        lmhash = ''
        nthash = ''

    cfg = AuthConfig(
        host=address,
        username=username,
        password=password,
        domain=domain,
        port=int(args.port),
        use_kerberos=args.k,
        aes_key=args.aesKey or "",
        kdc_host=args.dc_ip,
        nthash=nthash,
        lmhash=lmhash
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

            # Optionally resolve pipe owners via WMI before printing.
            owners = {}
            if not args.no_wmi:
                from pspipe.wmi import resolve_pipe_owners
                owners = resolve_pipe_owners(cfg, names)

            print("PSHost pipes on target:")
            for n in names:
                owner = owners.get(n)
                if owner:
                    print(f"   {n}  ({owner})")
                else:
                    print(f"   {n}")
            return 0

        if not args.pipe:
            print("[!] --pipe is required unless --list is used", file=sys.stderr)
            return 2

        # Optionally show pipe owner before connecting.
        if not args.no_wmi:
            from pspipe.wmi import resolve_pipe_owners
            owners = resolve_pipe_owners(cfg, [args.pipe])
            owner = owners.get(args.pipe)
            if owner:
                print(f"[*] Pipe owner: {owner}")
            else:
                print("[*] Pipe owner: (unknown)")

        try:
            conn.open_pipe(args.pipe)
        except Exception as exc:  # noqa: BLE001
            # Layer 2: an access-denied here means the pipe DACL didn't grant
            # your account access. That's expected and not worked around.
            print(f"[!] opening pipe failed: {exc}", file=sys.stderr)
            return 1

        session = PSRPSession(conn)
        session.open()

        try:
            if args.script:
                if not os.path.isfile(args.script):
                    print(f"[!] script file not found: {args.script}", file=sys.stderr)
                    return 1
                from charset_normalizer import from_path
                result = from_path(args.script).best()
                if result is None:
                    print(f"[!] could not detect encoding for: {args.script}", file=sys.stderr)
                    return 1
                session.run_command(str(result))
            elif args.command:
                session.run_command(args.command)
            else:
                print("Connected. Enter PowerShell commands; 'exit' to quit.")
                while True:
                    try:
                        line = input("PS> ").strip()
                    except EOFError:
                        break
                    if line in ("exit", "quit"):
                        break
                    if not line:
                        continue

                    # Accumulate continuation lines for incomplete blocks
                    block = line
                    while not _is_block_complete(block):
                        try:
                            block += "\n" + input(">> ")
                        except (EOFError, KeyboardInterrupt):
                            block = ""
                            print()
                            break

                    if not block.strip():
                        continue
                    try:
                        session.run_command(block)
                    except KeyboardInterrupt:
                        print()
        finally:
            session.close()
        return 0
    finally:
        conn.close()


if __name__ == "__main__":
    raise SystemExit(main())
