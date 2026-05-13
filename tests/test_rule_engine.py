"""Tests for the rule-based detection engine."""
from firewall.detectors.rule_engine import RuleEngine


r = RuleEngine()


# SQLi tests
def test_sqli_union_select():
    bad, reason = r.check("union select * from users")
    assert bad
    assert "SQLi" in reason


def test_sqli_or_1_equals_1():
    bad, _ = r.check("' or 1=1 --")
    assert bad


def test_sqli_drop_table():
    bad, _ = r.check("'; drop table users--")
    assert bad


def test_sqli_sleep():
    bad, _ = r.check("1' and sleep(5)--")
    assert bad


def test_sqli_information_schema():
    bad, _ = r.check("select * from information_schema.tables")
    assert bad


# XSS tests
def test_xss_script_tag():
    bad, reason = r.check("<script>alert(1)</script>")
    assert bad
    assert "XSS" in reason


def test_xss_onerror():
    bad, _ = r.check("<img src=x onerror=alert(1)>")
    assert bad


def test_xss_javascript_protocol():
    bad, _ = r.check("<a href='javascript:alert(1)'>")
    assert bad


def test_xss_iframe():
    bad, _ = r.check("<iframe src=evil.com></iframe>")
    assert bad


def test_xss_document_cookie():
    bad, _ = r.check("document.cookie")
    assert bad


# Benign tests (must NOT trigger)
def test_benign_normal_text():
    bad, _ = r.check("hello world this is fine")
    assert not bad


def test_benign_email():
    bad, _ = r.check("user@example.com")
    assert not bad


def test_benign_url():
    bad, _ = r.check("/api/users/profile?page=1")
    assert not bad


def test_benign_search_query():
    bad, _ = r.check("search for laptops under 50000")
    assert not bad
