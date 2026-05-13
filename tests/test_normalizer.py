"""Tests for the payload normalizer."""
from firewall.preprocessing.normalizer import PayloadNormalizer


n = PayloadNormalizer()


def test_empty_input():
    assert n.normalize("") == ""


def test_none_input():
    assert n.normalize(None) == ""


def test_lowercase():
    assert n.normalize("HELLO WORLD") == "hello world"


def test_url_decode_single():
    result = n.normalize("%53%45%4C%45%43%54")
    assert "select" in result


def test_url_decode_double():
    result = n.normalize("%2553%2545%254C%2545%2543%2554")
    assert "select" in result


def test_html_entity_hex():
    result = n.normalize("&#x3C;script&#x3E;")
    assert "<script>" in result


def test_html_entity_named():
    result = n.normalize("&lt;script&gt;")
    assert "<script>" in result


def test_sql_inline_comment_strip():
    result = n.normalize("SEL/*evil*/ECT")
    # comment becomes space, then we check both halves are present
    assert "sel" in result and "ect" in result
    assert "evil" not in result


def test_sql_dash_comment_strip():
    result = n.normalize("admin'-- secret")
    assert "secret" not in result


def test_whitespace_normalization():
    result = n.normalize("SELECT\t\t\nFROM\r\r users")
    assert "select from users" in result
