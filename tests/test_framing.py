import pytest

from crafty.core.framing import FrameReader, Framing, FrameTooLarge


def feeder(*chunks):
    """A recv(n) callable that yields the given chunks, then EOF."""
    data = bytearray(b"".join(chunks))

    def recv(n):
        if not data:
            return b""
        out = bytes(data[:n])
        del data[:n]
        return out

    return recv


def test_fixed():
    r = FrameReader(feeder(b"ABCDEFGH"), Framing.from_spec({"type": "fixed", "size": 4}))
    assert r.read_frame() == b"ABCD"
    assert r.read_frame() == b"EFGH"
    assert r.read_frame() is None


def test_bare_int_is_fixed():
    r = FrameReader(feeder(b"XYZ"), Framing.from_spec(3))
    assert r.read_frame() == b"XYZ"


def test_length_prefix_body_count():
    # 2-byte BE length = body length, then body
    msg = b"\x00\x05hello" + b"\x00\x03abc"
    r = FrameReader(feeder(msg), Framing.from_spec({
        "type": "length-prefix", "size": 2, "endian": "be", "counts": "body",
    }))
    assert r.read_frame() == b"\x00\x05hello"
    assert r.read_frame() == b"\x00\x03abc"
    assert r.read_frame() is None


def test_length_prefix_total_count():
    # length value includes the 4-byte header itself
    msg = b"\x00\x00\x00\x08data"  # total 8 = 4 header + 4 body
    r = FrameReader(feeder(msg), Framing.from_spec({
        "type": "length-prefix", "size": 4, "endian": "be", "counts": "total",
    }))
    assert r.read_frame() == msg


def test_length_prefix_little_endian_and_offset():
    # 1 byte pre-header, then 2-byte LE length
    msg = b"\xAA" + b"\x02\x00" + b"hi"
    r = FrameReader(feeder(msg), Framing.from_spec({
        "type": "length-prefix", "offset": 1, "size": 2, "endian": "le", "counts": "body",
    }))
    assert r.read_frame() == msg


def test_length_prefix_reassembles_across_recv_chunks():
    r = FrameReader(feeder(b"\x00", b"\x05he", b"ll", b"o"), Framing.from_spec({
        "type": "length-prefix", "size": 2,
    }))
    assert r.read_frame() == b"\x00\x05hello"


def test_delimiter_include_and_leftover():
    r = FrameReader(feeder(b"line1\r\nline2\r\n"), Framing.from_spec({
        "type": "delimiter", "delimiter": "\r\n", "include": True,
    }))
    assert r.read_frame() == b"line1\r\n"
    assert r.read_frame() == b"line2\r\n"
    assert r.read_frame() is None


def test_delimiter_exclude():
    r = FrameReader(feeder(b"a|b|"), Framing.from_spec({
        "type": "delimiter", "delimiter": "|", "include": False,
    }))
    assert r.read_frame() == b"a"
    assert r.read_frame() == b"b"


def test_fixed_reads_up_to_size_without_blocking_to_fill():
    # Regression: `read: N` must return a short banner immediately, not wait to
    # fill N bytes (which would time out against a server that then goes idle).
    calls = {"n": 0}
    def recv(n):
        calls["n"] += 1
        if calls["n"] == 1:
            return b"SSH-2.0-OpenSSH_9.6\r\n"
        raise AssertionError("fixed read must not call recv again to fill size")
    r = FrameReader(recv, Framing.from_spec({"read": 1024}))
    assert r.read_frame() == b"SSH-2.0-OpenSSH_9.6\r\n"
    assert calls["n"] == 1


def test_frame_too_large():
    r = FrameReader(feeder(b"\xFF\xFFxxxx"), Framing.from_spec({
        "type": "length-prefix", "size": 2, "max_message": 16,
    }))
    with pytest.raises(FrameTooLarge):
        r.read_frame()
