"""Regex-based detection for known SQLi/XSS patterns."""
import re
from typing import Tuple, Optional


SQLI_PATTERNS = [
    r"\bunion\s+select\b",
    r"\bor\s+\d+\s*=\s*\d+",
    r"\band\s+\d+\s*=\s*\d+",
    r"\bdrop\s+table\b",
    r"\binsert\s+into\b",
    r"\bdelete\s+from\b",
    r"\bselect\s+.*\s+from\b",
    r"\bsleep\s*\(",
    r"\bbenchmark\s*\(",
    r"\bwaitfor\s+delay\b",
    r"\bxp_cmdshell\b",
    r"\binformation_schema\b",
    r"'\s*or\s*'",
    r"'\s*=\s*'",
    r";\s*--",
]

XSS_PATTERNS = [
    r"<script[^>]*>",
    r"</script>",
    r"javascript:",
    r"on\w+\s*=",
    r"<iframe",
    r"<svg[^>]*on",
    r"<img[^>]*on\w+",
    r"document\.cookie",
    r"document\.write",
    r"\beval\s*\(",
    r"window\.location",
    r"alert\s*\(",
    r"<embed",
    r"<object",
]


class RuleEngine:
    def __init__(self):
        self.sqli_re = [re.compile(p, re.IGNORECASE) for p in SQLI_PATTERNS]
        self.xss_re = [re.compile(p, re.IGNORECASE) for p in XSS_PATTERNS]

    def check(self, payload: str) -> Tuple[bool, Optional[str]]:
        """Returns (is_malicious, reason)."""
        for pattern in self.sqli_re:
            if pattern.search(payload):
                return True, f"SQLi pattern: {pattern.pattern}"
        for pattern in self.xss_re:
            if pattern.search(payload):
                return True, f"XSS pattern: {pattern.pattern}"
        return False, None
