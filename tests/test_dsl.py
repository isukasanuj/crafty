import pytest

from crafty.core.dsl import Context, DSLError, resolve
from crafty.core.structs import StructRegistry


def ctx(**vars):
    return Context(variables=dict(vars))


def test_literals_and_hex_escape():
    assert resolve(r"\x50\x4b\x03\x04") == b"\x50\x4b\x03\x04"
    assert resolve(r"ab\ncd") == b"ab\ncd"


def test_hex_placeholder():
    assert resolve("{{hex:504b0304}}") == b"\x50\x4b\x03\x04"
    assert resolve("{{hex:50 4b 03 04}}") == b"\x50\x4b\x03\x04"


def test_int_placeholders():
    assert resolve("{{u16be:1}}") == b"\x00\x01"
    assert resolve("{{u32le:258}}") == b"\x02\x01\x00\x00"


def test_bare_variable_and_bytes_prefix():
    assert resolve("{{user}}", ctx(user="alice")) == b"alice"
    assert resolve("{{bytes:blob}}", ctx(blob=b"\x01\x02")) == b"\x01\x02"


def test_length_prefix_sugar():
    assert resolve("{{len16be:body}}{{bytes:body}}", ctx(body=b"hello")) == b"\x00\x05hello"


def test_expression_placeholder():
    assert resolve("{{= concat(u16be(len(body)), body)}}", ctx(body=b"hi")) == b"\x00\x02hi"


def test_pack_placeholder():
    assert resolve('{{pack:"!IH", 1, 2}}') == b"\x00\x00\x00\x01\x00\x02"


def test_randbytes_length():
    out = resolve("{{randbytes:16}}")
    assert len(out) == 16


def test_struct_placeholder():
    reg = StructRegistry.from_spec({"Greeting": [
        {"name": "magic", "type": "bytes", "len": 4},
        {"name": "version", "type": "u16be"},
        {"name": "length", "type": "u16be", "value": "len(body)"},
        {"name": "body", "type": "bytes", "len": "length"},
    ]})
    c = Context(variables={"u": b"hello"}, structs=reg)
    out = resolve("{{struct:Greeting(magic=b'CRFT', version=1, body=u)}}", c)
    assert out == b"CRFT\x00\x01\x00\x05hello"


def test_mixed_literal_and_placeholder():
    assert resolve(r"GET {{path}} HTTP/1.0\r\n", ctx(path="/x")) == b"GET /x HTTP/1.0\r\n"


def test_unknown_prefix_errors():
    with pytest.raises(DSLError, match="unknown placeholder prefix"):
        resolve("{{frobnicate:1}}")


def test_bad_expression_is_wrapped():
    with pytest.raises(DSLError):
        resolve("{{= __import__('os')}}")
