"""Evasion bypass tests - proves firewall resists encoding tricks.

These tests verify the full pipeline (normalizer + rule engine + ML)
correctly blocks payloads that would bypass naive regex matching.
"""
from firewall.engine import FirewallEngine


fw = FirewallEngine()


# === Case-based evasion ===
def test_evasion_case_mixed_sqli():
    allowed, _ = fw.inspect("SeLeCt * FrOm users WhErE 1=1", ip="10.0.0.1")
    assert not allowed


def test_evasion_case_mixed_xss():
    allowed, _ = fw.inspect("<ScRiPt>alert(1)</sCrIpT>", ip="10.0.0.2")
    assert not allowed


# === URL encoding evasion ===
def test_evasion_url_encoded_sqli():
    # ' OR 1=1 --
    allowed, _ = fw.inspect("%27%20OR%201%3D1%20--", ip="10.0.0.3")
    assert not allowed


def test_evasion_url_encoded_xss():
    # <script>alert(1)</script>
    allowed, _ = fw.inspect("%3Cscript%3Ealert(1)%3C/script%3E", ip="10.0.0.4")
    assert not allowed


def test_evasion_double_url_encoded():
    # double-encoded SELECT
    allowed, _ = fw.inspect("%2553%2545%254C%2545%2543%2554 from users", ip="10.0.0.5")
    assert not allowed


# === HTML entity evasion ===
def test_evasion_html_entity_xss():
    payload = "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;"
    allowed, _ = fw.inspect(payload, ip="10.0.0.6")
    assert not allowed


def test_evasion_html_named_entity():
    payload = "&lt;script&gt;alert(1)&lt;/script&gt;"
    allowed, _ = fw.inspect(payload, ip="10.0.0.7")
    assert not allowed


# === SQL comment evasion ===
def test_evasion_inline_comment():
    allowed, _ = fw.inspect("UNION/**/SELECT password FROM users", ip="10.0.0.8")
    assert not allowed


def test_evasion_multiline_comment():
    allowed, _ = fw.inspect("SEL/*xxxxxx*/ECT * FROM users", ip="10.0.0.9")
    assert not allowed


# === Benign (must NOT block) ===
def test_benign_simple():
    allowed, _ = fw.inspect("hello world", ip="10.0.1.1")
    assert allowed


def test_benign_email_login():
    allowed, _ = fw.inspect("user@example.com", ip="10.0.1.2")
    assert allowed


def test_benign_search():
    allowed, _ = fw.inspect("search for products", ip="10.0.1.3")
    assert allowed


def test_benign_url_path():
    allowed, _ = fw.inspect("/api/v1/users/123", ip="10.0.1.4")
    assert allowed


# === Rate limiting ===
def test_rate_limit_kicks_in():
    fw_test = FirewallEngine()
    test_ip = "192.168.99.99"
    
    # Default is 100/min - send 100 benign requests
    for _ in range(100):
        fw_test.inspect("hello", ip=test_ip)
    
    # 101st should be blocked
    allowed, reason = fw_test.inspect("hello", ip=test_ip)
    assert not allowed
    assert "Rate limit" in reason or "Blocked" in reason
