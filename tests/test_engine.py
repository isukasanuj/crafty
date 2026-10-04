import socket
import threading
import time

import pytest

from crafty.core import engine
from crafty.core.session import Session
from crafty.schema import Template


def free_port(kind=socket.SOCK_STREAM):
    s = socket.socket(socket.AF_INET, kind)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# --------------------------------------------------------------------------- #
# Client flow against a loopback TCP server
# --------------------------------------------------------------------------- #
def _tcp_length_prefixed_server(ready, stop, port):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(1)
    srv.settimeout(0.3)
    ready.set()
    while not stop.is_set():
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            continue
        with conn:
            conn.recv(1024)  # consume the probe
            conn.sendall(b"\x00\x05hello")  # 2-byte BE length prefix + body
    srv.close()


def test_client_flow_matches_length_prefixed_response():
    port = free_port()
    ready, stop = threading.Event(), threading.Event()
    th = threading.Thread(target=_tcp_length_prefixed_server, args=(ready, stop, port), daemon=True)
    th.start()
    ready.wait(2)

    t = Template.from_dict({
        "id": "probe",
        "transport": "tcp",
        "role": "client",
        "target": f"127.0.0.1:{port}",
        "socket": {"timeout": "3s"},
        "flow": [
            {
                "send": {"bytes": "ping"},
                "recv": {"type": "length-prefix", "size": 2, "endian": "be", "counts": "body"},
                "matchers": [{"type": "word", "part": "data", "words": ["hello"]}],
                "on_match": {"log": "got banner", "extract": {"banner": "{{data[2:]}}"}},
            }
        ],
    })
    s = Session(template=t)
    engine.run(s)
    stop.set()

    assert s.state == "done"
    assert s.stats.get("matched") == 1
    assert s.variables.get("banner") == b"hello"
    kinds = [e.kind for e in s.events.events]
    assert "send" in kinds and "recv" in kinds


# --------------------------------------------------------------------------- #
# Listener with selectivity
# --------------------------------------------------------------------------- #
def test_udp_listener_selective_response():
    port = free_port(socket.SOCK_DGRAM)
    t = Template.from_dict({
        "id": "poison",
        "transport": "udp",
        "role": "listener",
        "socket": {"bind": f"127.0.0.1:{port}"},
        "selectivity": {"respond_to": ["*.corp.local"], "ignore": ["*-canary*"]},
        "on_receive": {
            "extract": [{"name": "query", "type": "dsl", "expression": "str(data)"}],
            "respond": {"bytes": "{{= concat(b'ANSWER:', bytes(query))}}"},
            "capture": {"to": None, "value": "{{query}}"},
        },
    })
    s = Session(template=t)
    th = threading.Thread(target=engine.run, args=(s,), daemon=True)
    th.start()
    for _ in range(50):
        if s.state == "listening":
            break
        time.sleep(0.02)
    assert s.state == "listening"

    cli = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    cli.settimeout(1.5)

    # in-scope name -> answered
    cli.sendto(b"host1.corp.local", ("127.0.0.1", port))
    reply, _ = cli.recvfrom(4096)
    assert reply == b"ANSWER:host1.corp.local"

    # canary -> ignored (no reply)
    cli.sendto(b"foo-canary.corp.local", ("127.0.0.1", port))
    with pytest.raises(socket.timeout):
        cli.recvfrom(4096)

    # out-of-scope -> not answered
    cli.sendto(b"other.example.net", ("127.0.0.1", port))
    with pytest.raises(socket.timeout):
        cli.recvfrom(4096)

    s.request_stop()
    th.join(timeout=3)
    cli.close()

    assert s.stats.get("responses") == 1
    assert s.stats.get("observed") == 3


def test_analyze_mode_never_responds():
    port = free_port(socket.SOCK_DGRAM)
    t = Template.from_dict({
        "id": "poison",
        "transport": "udp",
        "role": "listener",
        "mode": "analyze",
        "socket": {"bind": f"127.0.0.1:{port}"},
        "on_receive": {
            "extract": [{"name": "query", "type": "dsl", "expression": "str(data)"}],
            "respond": {"bytes": "{{= bytes(query)}}"},
        },
    })
    s = Session(template=t)
    th = threading.Thread(target=engine.run, args=(s,), daemon=True)
    th.start()
    for _ in range(50):
        if s.state == "listening":
            break
        time.sleep(0.02)

    cli = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    cli.settimeout(1.0)
    cli.sendto(b"anything.corp.local", ("127.0.0.1", port))
    with pytest.raises(socket.timeout):
        cli.recvfrom(4096)

    s.request_stop()
    th.join(timeout=3)
    cli.close()
    assert s.stats.get("observed") == 1
    assert s.stats.get("responses", 0) == 0


# --------------------------------------------------------------------------- #
# dry-run and round-trip
# --------------------------------------------------------------------------- #
def test_dry_run_resolves_bytes_without_sending():
    t = Template.from_dict({
        "id": "dry",
        "transport": "tcp",
        "role": "client",
        "mode": "dry-run",
        "target": "10.255.255.1:65000",  # unreachable; must not be contacted
        "flow": [{"send": {"bytes": r"\x50\x4b{{u16be:1}}"}}],
    })
    s = Session(template=t)
    engine.run(s)
    assert s.state == "done"
    send_events = [e for e in s.events.events if e.kind == "send"]
    assert len(send_events) == 1
    assert send_events[0].data.get("note", "").startswith("dry-run")


def test_config_round_trips_through_save(tmp_path):
    raw = {
        "id": "rt",
        "transport": "tcp",
        "role": "client",
        "target": "{{RHOST}}:{{RPORT|88}}",
        "flow": [{"send": {"bytes": "{{user}}"}}],
    }
    t = Template.from_dict(raw)
    s = Session(template=t, params={"RHOST": "10.0.0.5"})
    out = tmp_path / "saved.yaml"
    s.save(str(out))

    reloaded = Template.from_file(str(out))
    assert reloaded.declared_params()["RHOST"] == "10.0.0.5"  # param persisted as default
    assert reloaded.role == "client"
