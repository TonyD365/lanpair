"""``lanpair``: try pairing and messaging between two machines without writing code.

    lanpair host                 show a pairing code, then print and send messages
    lanpair join [CODE]          pair with a host once, then print and send messages
    lanpair send TEXT            send one message from a paired device and exit
    lanpair devices              list the devices paired with this host
    lanpair forget DEVICE        unpair a device (its name or id)

Messages are plain text, or JSON with ``--json``. State lives under ``~/.lanpair/lanpair-cli/``
and keys in the OS key store, so pairing survives restarts.
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
import threading
import time
from collections.abc import Callable, Sequence
from typing import Any, TextIO

from .node import Device, Host, Message, PeerInfo
from .pairing import PairingError

APP = "lanpair-cli"


def _clean(text: str) -> str:
    """Text from the network, made safe to print: no terminal control sequences."""
    return "".join(c if c.isprintable() or c in "\t" else "�" for c in text)


def _show(body: Any) -> str:
    return _clean(body if isinstance(body, str) else json.dumps(body, ensure_ascii=False))


def _parse(text: str, as_json: bool) -> Any:
    if not as_json:
        return text
    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        raise SystemExit(f"lanpair: not valid JSON: {e}") from e


def _options(args: argparse.Namespace) -> dict[str, Any]:
    opts: dict[str, Any] = {"app": APP, "announce": not args.no_mdns, "port": args.port}
    if args.bind:
        opts["bind"] = args.bind
    if args.state_dir:
        opts["state_dir"] = args.state_dir
    return opts


def _make_host(args: argparse.Namespace) -> Host:
    return Host(args.name, **_options(args))


def _make_device(args: argparse.Namespace) -> Device:
    return Device(args.name, **_options(args))


def _chat(
    receive: Callable[[float], Message | None],
    send: Callable[[Any], None],
    as_json: bool,
    stdin: TextIO,
    out: TextIO,
    stop: threading.Event,
) -> None:
    """Print what arrives; send each line typed. Ends at end of input."""

    def printer() -> None:
        while not stop.is_set():
            msg = receive(0.2)
            if msg is not None:
                print(f"[{_clean(msg.sender.name)}] {_show(msg.body)}", file=out, flush=True)

    thread = threading.Thread(target=printer, daemon=True)
    thread.start()
    for line in stdin:
        line = line.rstrip("\r\n")
        if not line:
            continue
        try:
            send(_parse(line, as_json))
        except (OSError, ValueError, LookupError) as e:
            print(f"lanpair: not sent: {e}", file=out, flush=True)
    stop.set()
    thread.join(timeout=1)


def _host(args: argparse.Namespace, stdin: TextIO, out: TextIO) -> int:
    with _make_host(args) as host:
        if args.pair or not host.devices:
            address = args.address
            if address is None and args.bind and args.bind not in ("0.0.0.0", "::"):
                address = f"{args.bind}:{host.port}"
            offer = host.pairing_offer(address=address)
            print(f"Pairing as {host.name!r}. On the other machine run:", file=out)
            print(f"  lanpair join '{offer.to_uri()}'", file=out)
            if args.qr:
                try:
                    offer.print_qr()
                except PairingError as e:
                    print(f"({e})", file=out)
            print("This code works once, for 5 minutes. Keep it private.", file=out, flush=True)

            def announce() -> None:
                peer = host.wait_for_pairing(timeout=max(0.0, offer.expires - time.time()))
                if peer is not None:
                    print(f"Paired with {_clean(peer.name)!r}.", file=out, flush=True)

            threading.Thread(target=announce, daemon=True).start()
        names = ", ".join(_clean(d.name) for d in host.devices) or "none yet"
        print(f"Devices: {names}. Type a line to send it to all of them.", file=out, flush=True)

        def send(body: Any) -> None:
            for device_id, ok in host.broadcast(body, ack=True).items():
                if not ok:
                    peer = next((d for d in host.devices if d.device_id == device_id), None)
                    who = _clean(peer.name) if peer else device_id
                    print(f"lanpair: {who!r} did not confirm", file=out, flush=True)

        _chat(host.receive, send, args.json, stdin, out, threading.Event())
    return 0


def _device_paired(dev: Device, code: str | None, args: argparse.Namespace, out: TextIO) -> bool:
    if code is None and dev.host is not None:
        return True
    if code is None:
        print("Not paired yet: run 'lanpair host' on the other machine, then", file=out)
        print("  lanpair join '<the code it shows>'", file=out, flush=True)
        return False
    try:
        host = dev.pair(code.strip(), timeout=args.timeout)
    except PairingError as e:
        print(f"lanpair: pairing failed: {e}", file=out, flush=True)
        return False
    print(f"Paired with {_clean(host.name)!r}.", file=out, flush=True)
    return True


def _join(args: argparse.Namespace, stdin: TextIO, out: TextIO) -> int:
    with _make_device(args) as dev:
        if not _device_paired(dev, args.code, args, out):
            return 1
        assert dev.host is not None
        print(
            f"Talking to {_clean(dev.host.name)!r}. Type a line to send it.", file=out, flush=True
        )
        _chat(
            dev.receive,
            lambda body: dev.send(body, ack=True),
            args.json,
            stdin,
            out,
            threading.Event(),
        )
    return 0


def _send(args: argparse.Namespace, out: TextIO) -> int:
    body = _parse(" ".join(args.text), args.json)
    with _make_device(args) as dev:
        if not _device_paired(dev, None, args, out):
            return 1
        try:
            dev.send(body, ack=True, timeout=args.timeout)
        except (OSError, LookupError, ValueError) as e:
            print(f"lanpair: not sent: {e}", file=out, flush=True)
            return 1
    print("Sent.", file=out)
    return 0


def _find(devices: list[PeerInfo], which: str) -> PeerInfo | None:
    matches = [d for d in devices if which in (d.device_id, d.name)]
    return matches[0] if len(matches) == 1 else None


def _devices(args: argparse.Namespace, out: TextIO) -> int:
    host = _make_host(args)
    try:
        if not host.devices:
            print("No devices paired yet.", file=out)
        for d in host.devices:
            print(f"{d.device_id}  {_clean(d.name)}  {d.address or '-'}", file=out)
    finally:
        host.close()
    return 0


def _forget(args: argparse.Namespace, out: TextIO) -> int:
    host = _make_host(args)
    try:
        peer = _find(host.devices, args.device)
        if peer is None:
            print(f"lanpair: no single device named or with id {args.device!r}", file=out)
            return 1
        host.unpair(peer.device_id)
        print(f"Forgot {_clean(peer.name)!r}.", file=out)
    finally:
        host.close()
    return 0


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="lanpair",
        description="Try secure pairing and messaging between two machines on your LAN.",
    )
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--name", default=socket.gethostname(), help="this machine's name")
    common.add_argument("--json", action="store_true", help="send and show messages as JSON")
    common.add_argument("--port", type=int, default=0, help="UDP/TCP port (default: any)")
    common.add_argument("--bind", help="listen on this address only")
    common.add_argument("--no-mdns", action="store_true", help="no mDNS announce or lookup")
    common.add_argument("--state-dir", help="where to keep paired devices (default: ~/.lanpair)")
    common.add_argument("--timeout", type=float, default=10.0, help="seconds to wait (default 10)")
    sub = p.add_subparsers(dest="command", required=True)
    host = sub.add_parser("host", parents=[common], help="show a pairing code, then chat")
    host.add_argument("--pair", action="store_true", help="offer pairing even if paired")
    host.add_argument("--no-qr", dest="qr", action="store_false", help="don't print a QR code")
    host.add_argument("--address", help="ip:port to put in the code (default: this machine's)")
    join = sub.add_parser("join", parents=[common], help="pair with a host once, then chat")
    join.add_argument("code", nargs="?", help="the lanpair://pair?... code the host shows")
    send = sub.add_parser("send", parents=[common], help="send one message and exit")
    send.add_argument("text", nargs="+")
    sub.add_parser("devices", parents=[common], help="list paired devices")
    forget = sub.add_parser("forget", parents=[common], help="unpair a device")
    forget.add_argument("device", help="its name or id")
    return p


def main(
    argv: Sequence[str] | None = None, stdin: TextIO | None = None, out: TextIO | None = None
) -> int:
    args = parser().parse_args(argv)
    stdin = stdin or sys.stdin
    out = out or sys.stdout
    try:
        if args.command == "host":
            return _host(args, stdin, out)
        if args.command == "join":
            return _join(args, stdin, out)
        if args.command == "send":
            return _send(args, out)
        if args.command == "devices":
            return _devices(args, out)
        return _forget(args, out)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
