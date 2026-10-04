"""Guards for the whole shipped template library: every template must lint, and
every client template must resolve end-to-end in dry-run (bytes/structs/
expressions/framing), and every listener's response bytes must resolve. Plus two
live smoke tests driving shipped templates against loopback servers."""

import copy
import socket
import threading

import pytest
import yaml

from crafty.core import dsl, engine
from crafty.core.dsl import Context
from crafty.core.session import Session
from crafty.schema import Template
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TEMPLATES = sorted((REPO / "crafty" / "templates").rglob("*.yaml"))
DUMMY = {"RHOST": "127.0.0.1", "RPORT": "9", "USERS": "administrator", "QUERY": "example.com",
         "USER": "root", "FILENAME": "test", "PAYLOAD": "PING", "BODY": "crafty",
         "ATTACKER_IP": "127.0.0.1", "IFACE": "0.0.0.0", "LPORT": "0"}


def _ids():
    return [p.relative_to(REPO).as_posix() for p in TEMPLATES]


def test_library_is_nonempty():
    assert len(TEMPLATES) >= 100


@pytest.mark.parametrize("path", TEMPLATES, ids=_ids())
def test_template_lints(path):
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert Template(raw=raw, path=str(path)).lint() == []


@pytest.mark.parametrize("path", TEMPLATES, ids=_ids())
def test_template_resolves(path):
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    t = Template(raw=raw, path=str(path))
    if t.role == "client":
        r = copy.deepcopy(raw)
        r["mode"] = "dry-run"
        s = Session(template=Template.from_dict(r), params=dict(DUMMY))
        engine.run(s)
        assert s.state != "error", s.error
    else:
        resp = (raw.get("on_receive", {}) or {}).get("respond")
        if resp:
            v = dict(DUMMY, data=b"\x00" * 48, query="pc.corp.local", peer="10.0.0.9:1")
            dsl.resolve(resp["bytes"] if isinstance(resp, dict) else resp, Context(variables=v))


def _free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _serve_once(port, on_connect):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port)); srv.listen(1); srv.settimeout(3)
    ready = threading.Event()
    def run():
        ready.set()
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            srv.close(); return
        with conn:
            on_connect(conn)
        srv.close()
    th = threading.Thread(target=run, daemon=True); th.start(); ready.wait(1)
    return th


def test_live_banner_grab_template():
    port = _free_port()
    _serve_once(port, lambda c: c.sendall(b"SSH-2.0-OpenSSH_9.6\r\n"))
    t = Template.from_file(str(REPO / "crafty/templates/client/banner-ssh.yaml"))
    # drop preflight so the single-shot server isn't consumed by the open-check
    t.raw.get("tempo", {}).pop("preflight", None)
    s = Session(template=t, params={"RHOST": "127.0.0.1", "RPORT": str(port)})
    engine.run(s)
    assert s.state == "done"
    assert s.stats.get("matched") == 1


def test_live_line_probe_template():
    port = _free_port()
    def handler(c):
        c.recv(64)               # consume PING
        c.sendall(b"+PONG\r\n")
    _serve_once(port, handler)
    t = Template.from_file(str(REPO / "crafty/templates/client/probe-redis-ping.yaml"))
    t.raw.get("tempo", {}).pop("preflight", None)
    s = Session(template=t, params={"RHOST": "127.0.0.1", "RPORT": str(port)})
    engine.run(s)
    assert s.state == "done"
    assert s.stats.get("matched") == 1
