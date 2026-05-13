"""Payload normalizer - defeats common evasion techniques."""
import urllib.parse
import html
import re


class PayloadNormalizer:
    """Normalizes HTTP payloads to defeat evasion attempts."""

    def normalize(self, payload: str) -> str:
        if not payload:
            return ""

        result = str(payload)

        # multi-pass decode (attackers layer encodings)
        for _ in range(5):
            prev = result
            try:
                result = urllib.parse.unquote_plus(result)
                result = html.unescape(result)
            except Exception:
                break
            if result == prev:
                break

        result = self._decode_unicode(result)
        result = self._strip_sql_comments(result)
        result = self._normalize_whitespace(result)
        return result.lower()

    def _decode_unicode(self, text: str) -> str:
        try:
            return text.encode('utf-8').decode('unicode_escape')
        except Exception:
            return text

    def _strip_sql_comments(self, text: str) -> str:
        text = re.sub(r'/\*.*?\*/', ' ', text, flags=re.DOTALL)
        text = re.sub(r'--[^\n]*', ' ', text)
        text = re.sub(r'#[^\n]*', ' ', text)
        return text

    def _normalize_whitespace(self, text: str) -> str:
        return re.sub(r'[\s\t\n\r\x00\x0b]+', ' ', text).strip()
