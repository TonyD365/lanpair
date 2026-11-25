"""The lanpair command, end to end on 127.0.0.1 (mDNS off, keys in memory)."""

import io
import os
import re
import threading
import time

import pytest

from lanpair import Identity, cli


class Out(io.StringIO):
    """Output shared between threads."""

    def __init__(self):
        super().__init__()
        self.lock = threading.Lock()

    def write(self, s):
        with self.lock:
            return super().write(s)

    def text(self):
        with self.lock:
            return self.getvalue()


def wait_for(out, pattern, timeout=10.0):
    end = time.time() + timeout
    while time.time() < end:
        m = re.search(pattern, out.text())
        if m:
            return m
        time.sleep(0.05)
    raise AssertionError(f"{pattern!r} not in:\n{out.text()}")


@pytest.fixture
def keys(monkeypatch):
    ids = {"host": Identity.generate(), "device": Identity.generate()}
    make_host, make_device = cli.Host, cli.Device
    monkeypatch.setattr(
        cli, "_make_host", lambda a: make_host(a.name, identity=ids["host"], **cli._options(a))
    )
    monkeypatch.setattr(
        cli,
        "_make_device",
        lambda a: make_device(a.name, identity=ids["device"], **cli._options(a)),
    )
    return ids


def common(tmp_path, role):
    return ["--no-mdns", "--bind", "127.0.0.1", "--state-dir", str(tmp_path / role), "--name", role]


def run(argv, stdin, out):
    result = {}
    t = threading.Thread(
        target=lambda: result.setdefault("code", cli.main(argv, stdin, out)), daemon=True
    )
    t.start()
    return t, result


def pipe():
    r, w = os.pipe()
    return os.fdopen(r, "r"), os.fdopen(w, "w", buffering=1)


def test_pair_chat_send_list_and_forget(tmp_path, keys):
    host_in, host_keys = pipe()
    host_out = Out()
    host, host_result = run(["host", "--no-qr", *common(tmp_path, "desk")], host_in, host_out)
    code = wait_for(host_out, r"lanpair join '([^']+)'").group(1)

    dev_in, dev_keys = pipe()
    dev_out = Out()
    dev, dev_result = run(["join", code, *common(tmp_path, "room")], dev_in, dev_out)
    wait_for(dev_out, r"Paired with 'desk'")
    wait_for(host_out, r"Paired with 'room'")

    host_keys.write("hello room\n")
    wait_for(dev_out, r"\[desk\] hello room")
    dev_keys.write("hi desk\n")
    wait_for(host_out, r"\[room\] hi desk")

    dev_keys.close()
    dev.join(10)
    assert dev_result["code"] == 0

    out = Out()
    assert (
        cli.main(
            ["send", "--json", '{"type": "checkout"}', *common(tmp_path, "room")],
            io.StringIO(),
            out,
        )
        == 0
    )
    wait_for(host_out, r'\[room\] \{"type": "checkout"\}')

    host_keys.close()
    host.join(10)
    assert host_result["code"] == 0

    out = Out()
    cli.main(["devices", *common(tmp_path, "desk")], io.StringIO(), out)
    assert "room" in out.text()
    out = Out()
    assert cli.main(["forget", "room", *common(tmp_path, "desk")], io.StringIO(), out) == 0
    out = Out()
    cli.main(["devices", *common(tmp_path, "desk")], io.StringIO(), out)
    assert "No devices paired yet." in out.text()


def test_send_without_pairing_explains(tmp_path, keys):
    out = Out()
    assert cli.main(["send", "hi", *common(tmp_path, "room")], io.StringIO(), out) == 1
    assert "lanpair host" in out.text()


def test_join_with_a_bad_code_fails(tmp_path, keys):
    out = Out()
    assert (
        cli.main(["join", "lanpair://pair?nope", *common(tmp_path, "room")], io.StringIO(), out)
        == 1
    )
    assert "pairing failed" in out.text()


def test_bad_json_is_refused(tmp_path, keys):
    with pytest.raises(SystemExit, match="not valid JSON"):
        cli.main(["send", "--json", "{oops", *common(tmp_path, "room")], io.StringIO(), Out())


def test_terminal_control_sequences_are_not_printed():
    shown = cli._show("\x1b[2J\x1b]0;owned\x07text\n")
    assert "\x1b" not in shown and "\x07" not in shown and "\n" not in shown
    assert shown.endswith("text�")
    assert cli._show({"a": "\x1b"}) == '{"a": "\\u001b"}'
