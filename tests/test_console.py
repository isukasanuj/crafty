import io
import socket
import time

from crafty.console.repl import Console


def free_udp_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def make_console():
    return Console(stdout=io.StringIO())  # default resolves to the bundled library


def out(con):
    return con.stdout.getvalue()


def test_use_set_show_roundtrip():
    con = make_console()
    con.do_use("length-prefixed-probe")
    assert con.active is not None
    con.do_set("RHOST 10.1.2.3")
    con.do_set("rate 10")
    con.do_show("options")
    text = out(con)
    assert "length-prefixed-probe" in text
    assert "RHOST" in text
    # override is applied into the resolved config
    assert con._resolved_raw()["tempo"]["rate"] == "10"
    assert con.params["RHOST"] == "10.1.2.3"


def test_search_finds_by_tag_and_role():
    con = make_console()
    con.do_search("role:listener")
    text = out(con)
    assert "selective-udp-responder" in text
    assert "llmnr-poison" in text

    con2 = make_console()
    con2.do_search("tag:struct")
    assert "length-prefixed-probe" in out(con2)


def test_explain_in_console():
    con = make_console()
    con.do_explain("tcp-banner")
    assert "banner" in out(con).lower()


def test_run_listener_backgrounds_and_kill():
    con = make_console()
    con.do_use("selective-udp-responder")
    port = free_udp_port()
    con.do_set(f"LPORT {port}")
    # bind to loopback for the test
    con.do_set("bind 127.0.0.1:%d" % port)
    con.do_run("-j")
    # a session should be registered and listening
    sessions = con.registry.all()
    assert len(sessions) == 1
    s = sessions[0]
    for _ in range(50):
        if s.state == "listening":
            break
        time.sleep(0.02)
    assert s.state == "listening"

    # selectivity works live
    cli = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    cli.settimeout(1.5)
    cli.sendto(b"pc1.corp.local", ("127.0.0.1", port))
    reply, _ = cli.recvfrom(4096)
    assert reply == b"ANSWER pc1.corp.local"
    cli.close()

    con.do_sessions("")
    assert "udp/listener" in out(con)

    con.do_kill(str(s.id))
    assert s.state == "killed"


def test_save_active_context(tmp_path):
    con = make_console()
    con.do_use("length-prefixed-probe")
    con.do_set("RHOST 10.9.9.9")
    target = tmp_path / "saved.yaml"
    con.do_save(str(target))
    assert target.exists()
    text = target.read_text()
    assert "10.9.9.9" in text  # param persisted into defaults
