import pytest

from crafty.core.structs import StructDef, StructError, StructRegistry

GREETING = [
    {"name": "magic", "type": "bytes", "len": 4},
    {"name": "version", "type": "u16be"},
    {"name": "length", "type": "u16be", "value": "len(body)"},
    {"name": "body", "type": "bytes", "len": "length"},
]


def test_pack_computes_length_prefix():
    s = StructDef.from_spec("Greeting", GREETING)
    out = s.pack({"magic": b"CRFT", "version": 1, "body": b"hello"})
    assert out == b"CRFT" + b"\x00\x01" + b"\x00\x05" + b"hello"


def test_parse_is_symmetric_with_pack():
    s = StructDef.from_spec("Greeting", GREETING)
    raw = s.pack({"magic": b"CRFT", "version": 2, "body": b"abcdef"})
    values, consumed = s.parse(raw)
    assert consumed == len(raw)
    assert values["magic"] == b"CRFT"
    assert values["version"] == 2
    assert values["length"] == 6
    assert values["body"] == b"abcdef"


def test_parse_uses_earlier_field_as_length():
    s = StructDef.from_spec("LV", [
        {"name": "n", "type": "u8"},
        {"name": "payload", "type": "bytes", "len": "n"},
    ])
    values, consumed = s.parse(b"\x03ABCtrailing")
    assert values == {"n": 3, "payload": b"ABC"}
    assert consumed == 4  # did not over-read into "trailing"


def test_str_field_roundtrip():
    s = StructDef.from_spec("Named", [
        {"name": "len", "type": "u8", "value": "len(name)"},
        {"name": "name", "type": "str", "len": "len"},
    ])
    raw = s.pack({"name": "bob"})
    assert raw == b"\x03bob"
    values, _ = s.parse(raw)
    assert values["name"] == "bob"


def test_rest_consumes_remainder():
    s = StructDef.from_spec("R", [
        {"name": "code", "type": "u8"},
        {"name": "rest", "type": "rest"},
    ])
    values, consumed = s.parse(b"\x01the rest of it")
    assert values["code"] == 1
    assert values["rest"] == b"the rest of it"
    assert consumed == len(b"\x01the rest of it")


def test_parse_truncated_raises():
    s = StructDef.from_spec("LV", [
        {"name": "n", "type": "u16be"},
        {"name": "payload", "type": "bytes", "len": "n"},
    ])
    with pytest.raises(StructError, match="only"):
        s.parse(b"\x00\x10short")


def test_pack_wrong_fixed_length_raises():
    s = StructDef.from_spec("Fixed", [{"name": "magic", "type": "bytes", "len": 4}])
    with pytest.raises(StructError, match="expected 4 bytes"):
        s.pack({"magic": b"TOO LONG"})


def test_registry():
    reg = StructRegistry.from_spec({"Greeting": GREETING})
    assert "Greeting" in reg
    assert reg.get("Greeting").pack({"magic": b"CRFT", "version": 1, "body": b"x"})
    with pytest.raises(StructError, match="unknown struct"):
        reg.get("Nope")


def test_bad_definition_missing_len():
    with pytest.raises(StructError, match="needs a 'len'"):
        StructDef.from_spec("Bad", [{"name": "body", "type": "bytes"}])
