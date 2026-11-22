"""Pre-LLM guardrail engine: prompt-injection detection + PII/secret redaction.

Design notes
------------
* Detection runs on a *normalized* copy of the prompt (Unicode NFKC, zero-width
  characters stripped, lowercase, collapsed whitespace). Attackers love tricks
  like "ign​ore previous instructions" or full-width letters; normalizing
  first defeats the cheap versions of those.
* Base64 blobs are decoded and re-scanned, since "decode this and follow it"
  is a common smuggling technique.
* Rule weights are combined with a noisy-OR: risk = 1 - prod(1 - w_i).
  One strong signal can block on its own; several weak ones add up, and the
  score never exceeds 1.0.
* Regex heuristics are a first layer, not a complete defence. See README
  "Limitations" — a production system would add a trained classifier.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass, field

from app.schemas import Action, Finding

# --------------------------------------------------------------- normalizing
_INVISIBLE = re.compile(r"[​-‏‪-‮⁠-⁤﻿­]")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_WS = re.compile(r"\s+")


def strip_invisible(text: str) -> str:
    """Remove zero-width / bidi-override / control characters."""
    return _CONTROL.sub("", _INVISIBLE.sub("", text))


def normalize(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    text = strip_invisible(text)
    return _WS.sub(" ", text).lower().strip()


# ------------------------------------------------------ prompt-injection rules
@dataclass(frozen=True)
class InjectionRule:
    rule_id: str
    category: str
    description: str
    pattern: re.Pattern[str]
    weight: float


def _r(p: str) -> re.Pattern[str]:
    return re.compile(p, re.IGNORECASE)


INJECTION_RULES: tuple[InjectionRule, ...] = (
    InjectionRule(
        "PI-001", "instruction_override",
        "Attempts to override or discard prior instructions",
        _r(r"\b(ignore|disregard|forget|override|bypass|skip)\b.{0,40}?"
           r"\b(previous|prior|above|earlier|preceding|all|any|your|the|system)\b.{0,40}?"
           r"\b(instructions?|prompts?|rules?|directions?|guidelines?|context)\b"),
        0.85,
    ),
    InjectionRule(
        "PI-002", "system_prompt_extraction",
        "Attempts to extract the system prompt or hidden configuration",
        _r(r"\b(reveal|show|print|repeat|output|display|leak|dump|tell me|what (is|are|was|were))\b"
           # Require a determiner pointing at THIS model's prompt ("your", "the"),
           # so "how does a system prompt work?" isn't a false positive.
           r".{0,30}?\b(your|the|this|its|current)\s+(full\s+|entire\s+|exact\s+)?"
           r"(system|hidden|initial|original|secret|internal|developer)\s+"
           r"(prompt|instructions?|message|rules|configuration)\b"),
        0.8,
    ),
    InjectionRule(
        "PI-003", "role_hijack",
        "Attempts to reassign the model's role or identity",
        _r(r"\byou are (now|no longer)\b|\bfrom now on,? (you|act|respond)\b"
           r"|\b(act|behave|respond) as (an? )?(unrestricted|unfiltered|uncensored|evil|jailbroken)\b"
           r"|\bpretend (that )?you (have no|are not bound|don'?t have)\b"),
        0.55,
    ),
    InjectionRule(
        "PI-004", "jailbreak_persona",
        "Known jailbreak personas / modes",
        _r(r"\b(dan mode|do anything now|developer mode|god mode|jailbreak(ed)?|aim mode|stan mode)\b"),
        0.6,
    ),
    InjectionRule(
        "PI-005", "delimiter_injection",
        "Chat-template or role delimiters embedded in user text",
        _r(r"<\|?\s*(im_start|im_end|system|endoftext|assistant)\s*\|?>"
           r"|\[/?(inst|sys|system)\]|<<\s*sys\s*>>|^#{2,}\s*(system|instructions?)\b"),
        0.6,
    ),
    InjectionRule(
        "PI-006", "safety_bypass",
        "Requests to disable safety controls or filters",
        _r(r"\b(without|no|disable|turn off|remove|ignore)\b.{0,25}?"
           r"\b(restrictions?|filters?|guardrails?|safety|censorship|limitations|content polic(y|ies))\b"),
        0.45,
    ),
    InjectionRule(
        "PI-007", "markdown_exfiltration",
        "Markdown image pointing at an external URL (classic data-exfil channel)",
        _r(r"!\[[^\]]*\]\(\s*https?://"),
        0.5,
    ),
    InjectionRule(
        "PI-008", "encoded_instruction",
        "Instructs the model to decode and execute hidden content",
        _r(r"\b(decode|decrypt|deobfuscate|translate)\b.{0,30}?\b(base64|rot13|hex|cipher)\b"
           r".{0,40}?\b(follow|execute|run|obey|do what)\b"),
        0.5,
    ),
    # Low-confidence "monitor" rule: its weight sits below the default block
    # threshold, so on its own it only FLAGS the prompt for the dashboard.
    # "What are your rules for returns?" is a normal customer question, but
    # combined with any other signal (e.g. a role hijack) it tips into a block.
    InjectionRule(
        "PI-009", "instruction_probing",
        "Asks about the model's own rules or instructions (low confidence, flag only)",
        _r(r"\b(what (are|were)|list|tell me|show me)\b.{0,15}?\byour\s+"
           r"(rules|instructions|guidelines|directives|constraints)\b"),
        0.35,
    ),
)

_B64_CANDIDATE = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")


def _decoded_base64_segments(text: str, limit: int = 5) -> list[str]:
    """Decode up to `limit` base64-looking chunks that turn into readable text."""
    out: list[str] = []
    for match in _B64_CANDIDATE.finditer(text):
        if len(out) >= limit:
            break
        chunk = match.group(0)
        try:
            decoded = base64.b64decode(chunk + "=" * (-len(chunk) % 4), validate=True)
            as_text = decoded.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if as_text.isprintable() or "\n" in as_text:
            out.append(as_text)
    return out


def detect_injection(prompt: str) -> tuple[float, list[Finding]]:
    """Return (risk_score, findings) for a raw user prompt."""
    views = [("", normalize(prompt))]
    views += [("B64:", normalize(seg)) for seg in _decoded_base64_segments(prompt)]

    findings: list[Finding] = []
    seen: set[str] = set()
    for prefix, view in views:
        for rule in INJECTION_RULES:
            key = prefix + rule.rule_id
            if key in seen or not rule.pattern.search(view):
                continue
            seen.add(key)
            findings.append(Finding(
                rule_id=key,
                category=rule.category,
                description=rule.description + (" (inside base64 payload)" if prefix else ""),
                weight=rule.weight,
            ))

    survival = 1.0
    for f in findings:
        survival *= 1.0 - f.weight
    return round(1.0 - survival, 3), findings


# ------------------------------------------------------- PII & secret redaction
def _luhn_ok(candidate: str) -> bool:
    digits = [int(c) for c in candidate if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


@dataclass(frozen=True)
class PIIRule:
    label: str
    pattern: re.Pattern[str]
    validator: object = None   # optional callable(str) -> bool


# Order matters: secrets first (they contain digits/letters that other rules
# might partially match), then structured financial/government IDs, then
# looser patterns like phone numbers.
PII_RULES: tuple[PIIRule, ...] = (
    PIIRule("PRIVATE_KEY", re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----")),
    PIIRule("AWS_ACCESS_KEY", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    PIIRule("OPENAI_API_KEY", re.compile(r"\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}\b")),
    PIIRule("GITHUB_TOKEN", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    PIIRule("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    PIIRule("GENERIC_SECRET", re.compile(
        r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|token)\s*[:=]\s*['\"]?[^\s'\"]{6,}")),
    PIIRule("EMAIL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    PIIRule("CREDIT_CARD", re.compile(r"\b(?:\d[ -]?){12,18}\d\b"), _luhn_ok),
    PIIRule("US_SSN", re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")),
    PIIRule("PHONE_US", re.compile(
        r"(?<!\w)(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")),
)


@dataclass
class RedactionResult:
    text: str
    counts: dict[str, int] = field(default_factory=dict)

    @property
    def redacted(self) -> bool:
        return bool(self.counts)


def redact_pii(text: str) -> RedactionResult:
    """Mask PII and secrets with typed placeholders like [REDACTED:EMAIL]."""
    counts: dict[str, int] = {}

    for rule in PII_RULES:
        def _sub(m: re.Match[str], rule: PIIRule = rule) -> str:
            if rule.validator and not rule.validator(m.group(0)):  # type: ignore[operator]
                return m.group(0)
            counts[rule.label] = counts.get(rule.label, 0) + 1
            return f"[REDACTED:{rule.label}]"

        text = rule.pattern.sub(_sub, text)

    return RedactionResult(text=text, counts=counts)


# ---------------------------------------------------------------- the engine
@dataclass
class InputVerdict:
    action: Action
    risk_score: float
    sanitized_prompt: str
    findings: list[Finding]
    redactions: dict[str, int]


class InputGuard:
    def __init__(self, block_threshold: float = 0.7) -> None:
        self.block_threshold = block_threshold

    def inspect(self, prompt: str) -> InputVerdict:
        # 1. Detect injection on the ORIGINAL text (before redaction changes it).
        risk, findings = detect_injection(prompt)

        # 2. Redact PII/secrets from what we'd forward upstream.
        redaction = redact_pii(strip_invisible(prompt))

        if risk >= self.block_threshold:
            action = Action.BLOCK
        elif redaction.redacted:
            action = Action.REDACT
        else:
            action = Action.ALLOW

        return InputVerdict(
            action=action,
            risk_score=risk,
            sanitized_prompt=redaction.text,
            findings=findings,
            redactions=redaction.counts,
        )
