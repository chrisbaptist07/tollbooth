import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import pytest
import tollbooth as t


def test_dechunk():
    assert t.dechunk(b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n") == b"hello world"


def test_parse_response_gzip():
    import gzip
    raw = b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n" + gzip.compress(b"hi")
    status, headers, body = t.parse_response(raw)
    assert status.endswith("200 OK") and body == b"hi"


def test_text_roundtrip_and_content_length():
    f = t.Flow(1, "GET", "", [])
    t.apply_text(f, "post http://localhost/login HTTP/1.1\nHost: localhost\nContent-Length: 999\n\nu=a&p=b")
    assert (f.method, f.path, f.body) == ("POST", "/login", b"u=a&p=b")
    assert b"Content-Length: 7\r\n" in t.build_request_bytes(f)  # recomputed, not 999


def test_rules():
    rules = [{"target": "request", "match": "false", "replace": "true", "enabled": True},
             {"target": "request", "match": r"id=\d+", "replace": "id=1", "regex": True},
             {"target": "response", "match": "x", "replace": "y"}]
    assert t.apply_rules("request", "admin=false&id=42", rules) == "admin=true&id=1"


def test_intruder_sniper_and_ram():
    req = "GET http://h/?a=§1§&b=§2§ HTTP/1.1\n\n"
    sniper = t.intruder_jobs(req, ["X", "Y"], "sniper")
    assert [j[2].split("\n")[0] for j in sniper] == [
        "GET http://h/?a=X&b=2 HTTP/1.1", "GET http://h/?a=Y&b=2 HTTP/1.1",
        "GET http://h/?a=1&b=X HTTP/1.1", "GET http://h/?a=1&b=Y HTTP/1.1"]
    ram = t.intruder_jobs(req, ["Z"], "ram")
    assert ram[0][2].startswith("GET http://h/?a=Z&b=Z")


def test_intruder_validation():
    with pytest.raises(ValueError):
        t.intruder_jobs("GET http://h/ HTTP/1.1\n\n", ["x"], "sniper")
    with pytest.raises(ValueError):
        t.intruder_jobs("GET http://h/§a HTTP/1.1\n\n", ["x"], "sniper")


def test_decoders():
    assert t.DECODERS["b64dec"]("aGVsbG8") == "hello"  # missing padding tolerated
    assert t.DECODERS["urlenc"]("a b&c") == "a%20b%26c"
    assert t.DECODERS["sha256"]("a").startswith("ca978112")


def test_compare():
    d = t.compare("a\nb", "a\nc")
    assert ["-", "b"] in d and ["+", "c"] in d


def test_scope():
    s = t.State(["localhost"])
    assert s.in_scope("localhost") and not s.in_scope("example.com")
    s.scope = ["*"]
    assert s.in_scope("example.com")
