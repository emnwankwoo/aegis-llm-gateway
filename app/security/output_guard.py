"""Post-LLM guardrail engine (OWASP LLM05 Improper Output Handling, LLM07 Prompt Leakage).

Checks, in order:
1. Canary token leak      -> BLOCK. A random token is planted in the system
                             prompt per request; seeing it in the output is
                             near-certain proof the system prompt leaked.
2. System-prompt overlap  -> BLOCK. Catches paraphrase-free leaks even if the
                             canary was stripped (8-word shingle match).
3. Secrets / PII          -> REDACT (same detectors as the input guard).
4. Untrusted URLs         -> REDACT. Non-allowlisted domains, plain http, raw
                             IP hosts and external markdown images are removed.
5. Dangerous shell code   -> REDACT. Lines like `curl ... | sh` or `rm -rf /`.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from app.schemas import Action, Finding
from app.security.input_guard import normalize, redact_pii

_MD_IMAGE = re.compile(r"!\[[^\]]*\]\(\s*(https?://[^)\s]+)[^)]*\)")
_URL = re.compile(r"\b(?:https?|ftp)://[^\s<>()\"'`\]]+", re.IGNORECASE)

_DANGEROUS_CODE: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("pipe_to_shell", re.compile(r"\b(curl|wget|iwr|invoke-webrequest)\b[^\n|]*\|\s*(sudo\s+)?(ba|z)?sh\b", re.I)),
    ("recursive_root_delete", re.compile(r"\brm\s+-[a-z]*r[a-z]*f?[a-z]*\s+(/|~|\*)(\s|$)", re.I)),
    ("encoded_powershell", re.compile(r"\bpowershell(\.exe)?\b[^\n]*\s-(e|enc|encodedcommand)\s", re.I)),
    ("invoke_expression", re.compile(r"\b(iex|invoke-expression)\b\s*\(?\s*(\(|new-object|\$)", re.I)),
    ("fork_bomb", re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:")),
    ("disk_wipe", re.compile(r"\b(mkfs(\.\w+)?\s+/dev/|dd\s+if=/dev/(zero|random)\s+of=/dev/)", re.I)),
)


@dataclass
class OutputVerdict:
    action: Action
    risk_score: float
    text: str | None
    findings: list[Finding]
    redactions: dict[str, int]


def _shingles(text: str, size: int = 8) -> set[str]:
    words = normalize(text).split()
    return {" ".join(words[i:i + size]) for i in range(max(0, len(words) - size + 1))}


class OutputGuard:
    def __init__(self, allowed_domains: list[str], system_prompt: str) -> None:
        self.allowed_domains = [d.lower().lstrip(".") for d in allowed_domains]
        self._system_shingles = _shingles(system_prompt)

    # ---------------------------------------------------------------- helpers
    def _domain_allowed(self, url: str) -> bool:
        try:
            parts = urlsplit(url)
        except ValueError:
            return False
        host = (parts.hostname or "").lower()
        if parts.scheme != "https" or not host:
            return False
        try:
            ipaddress.ip_address(host)
            return False                     # raw IPs are never trusted
        except ValueError:
            pass
        return any(host == d or host.endswith("." + d) for d in self.allowed_domains)

    # ------------------------------------------------------------------ main
    def inspect(self, text: str, canary: str | None = None) -> OutputVerdict:
        findings: list[Finding] = []

        # 1 + 2: prompt leakage -> hard block
        if canary and canary in text:
            findings.append(Finding(rule_id="OUT-001", category="system_prompt_leak",
                                    description="Canary token from system prompt found in output",
                                    weight=1.0))
        elif self._system_shingles and self._system_shingles & _shingles(text):
            findings.append(Finding(rule_id="OUT-002", category="system_prompt_leak",
                                    description="Output reproduces system-prompt text verbatim",
                                    weight=0.9))
        if findings:
            return OutputVerdict(Action.BLOCK, findings[0].weight, None, findings, {})

        # 3: secrets / PII
        redaction = redact_pii(text)
        text, counts = redaction.text, dict(redaction.counts)
        if redaction.redacted:
            findings.append(Finding(rule_id="OUT-003", category="sensitive_data",
                                    description=f"Masked sensitive data: {', '.join(sorted(counts))}",
                                    weight=0.6))

        # 4: URLs (markdown images first — they auto-load in many UIs)
        removed_urls = 0

        def _strip_image(m: re.Match[str]) -> str:
            nonlocal removed_urls
            removed_urls += 1
            return "[IMAGE REMOVED: external image]"

        text = _MD_IMAGE.sub(_strip_image, text)

        def _check_url(m: re.Match[str]) -> str:
            nonlocal removed_urls
            url = m.group(0).rstrip(".,;:!?")
            trailing = m.group(0)[len(url):]
            if self._domain_allowed(url):
                return m.group(0)
            removed_urls += 1
            return "[URL REMOVED: untrusted destination]" + trailing

        text = _URL.sub(_check_url, text)
        if removed_urls:
            counts["UNTRUSTED_URL"] = removed_urls
            findings.append(Finding(rule_id="OUT-004", category="untrusted_url",
                                    description=f"Removed {removed_urls} untrusted URL(s)",
                                    weight=0.5))

        # 5: dangerous shell snippets — remove the whole offending line
        hits: list[str] = []
        lines = text.split("\n")
        for i, line in enumerate(lines):
            for name, pattern in _DANGEROUS_CODE:
                if pattern.search(line):
                    hits.append(name)
                    lines[i] = "[REMOVED: potentially destructive command]"
                    break
        if hits:
            text = "\n".join(lines)
            counts["DANGEROUS_CODE"] = len(hits)
            findings.append(Finding(rule_id="OUT-005", category="unsafe_code",
                                    description=f"Removed dangerous command(s): {', '.join(sorted(set(hits)))}",
                                    weight=0.7))

        survival = 1.0
        for f in findings:
            survival *= 1.0 - f.weight
        risk = round(1.0 - survival, 3)
        action = Action.REDACT if findings else Action.ALLOW
        return OutputVerdict(action, risk, text, findings, counts)
