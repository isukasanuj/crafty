import hashlib

import pytest

from crafty.core import expr
from crafty.core.expr import ExprError, evaluate, evaluate_bytes


def test_arithmetic_and_refs():
    assert evaluate("1 + 2 * 3") == 7
    assert evaluate("a + b", {"a": 10, "b": 5}) == 15
    assert evaluate("len(x)", {"x": b"hello"}) == 5


def test_slicing():
    assert evaluate("data[0:2]", {"data": b"ABCD"}) == b"AB"
    assert evaluate("data[-1]", {"data": b"ABCD"}) == ord("D")


def test_int_packers_explicit_endianness():
    assert evaluate("u16be(1)") == b"\x00\x01"
    assert evaluate("u16le(1)") == b"\x01\x00"
    assert evaluate("u32be(258)") == b"\x00\x00\x01\x02"


def test_length_prefix_idiom():
    out = evaluate("concat(u16be(len(body)), body)", {"body": b"hello"})
    assert out == b"\x00\x05hello"


def test_crypto_helpers():
    assert evaluate("sha256(x)", {"x": b"abc"}) == hashlib.sha256(b"abc").digest()
    assert evaluate("md5(x)", {"x": b""}) == hashlib.md5(b"").digest()
    assert evaluate("crc32(x)", {"x": b"123456789"}) == 0xCBF43926


def test_crc16_ccitt_false_known_vector():
    # CRC-16/CCITT-FALSE of "123456789" is 0x29B1
    assert evaluate("crc16(x)", {"x": b"123456789"}) == 0x29B1


def test_encoding_roundtrip():
    assert evaluate("b64e(x)", {"x": b"hi"}) == b"aGk="
    assert evaluate("b64d(x)", {"x": "aGk="}) == b"hi"


def test_ternary_is_allowed_but_not_control_flow():
    assert evaluate("1 if flag else 2", {"flag": True}) == 1
    assert evaluate("1 if flag else 2", {"flag": False}) == 2


@pytest.mark.parametrize(
    "bad",
    [
        "__import__('os').system('x')",
        "().__class__",
        "data.decode()",
        "[i for i in range(3)]",
        "lambda: 1",
        "open('x')",
        "eval('1')",
    ],
)
def test_sandbox_rejects_dangerous_expressions(bad):
    with pytest.raises(ExprError):
        evaluate(bad, {"data": b"x"})


def test_unknown_function_is_clear_error():
    with pytest.raises(ExprError, match="unknown function"):
        evaluate("frobnicate(1)")


def test_int_has_no_implicit_width_on_the_wire():
    with pytest.raises(ExprError, match="no implicit byte width"):
        evaluate_bytes("1 + 1")


def test_evaluate_bytes_coerces_str():
    assert evaluate_bytes("name", {"name": "alice"}) == b"alice"
