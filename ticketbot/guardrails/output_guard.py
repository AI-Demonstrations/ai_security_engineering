"""OUTPUT guardrail — catches problematic responses before they reach the customer.

It assumes the input guardrail has already failed, and checks what actually came out:
  * system-prompt leakage  — canary token or verbatim prompt text   (OWASP LLM07, ATLAS AML.T0056)
  * exfiltration links     — markdown images/links to non-allowlisted domains; an image URL
                             is fetched by the customer's mail client, carrying data out
                             with no click                                     (OWASP LLM05)
  * PII                    — card numbers (Luhn-checked), SSNs, phone numbers, emails outside
                             the company domain are redacted                    (OWASP LLM02)
  * size                   — replies over MAX_REPLY_CHARS are blocked          (OWASP LLM10)

Leakage and exfiltration BLOCK the reply (it is replaced by a safe fallback). PII is
REDACTED, since the rest of the reply may still be useful.
"""

import re
from dataclasses import dataclass, field
from typing import List
from urllib.parse import urlparse

MAX_REPLY_CHARS = 1500
ALLOWED_DOMAINS = {"support.example.com", "example.com"}
FALLBACK = "Thanks for contacting us. A support specialist will reply to your ticket shortly."

CARD = re.compile(r"\b(?:\d[ -]?){13,19}\b")
SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
PHONE = re.compile(r"\b(?:\+?1[ .-]?)?\(?\d{3}\)?[ .-]\d{3}[ .-]\d{4}\b")
EMAIL = re.compile(r"\b[\w.+-]+@([\w-]+\.[\w.-]+)\b")
LINK = re.compile(r"!?\[[^\]]*\]\((\S+?)\)|https?://\S+")


@dataclass
class Verdict:
    allowed: bool
    text: str
    reasons: List[str] = field(default_factory=list)


def luhn_ok(digits):
    total, alt = 0, False
    for d in reversed(digits):
        n = int(d) * (2 if alt else 1)
        total += n - 9 if n > 9 else n
        alt = not alt
    return total % 10 == 0


def redact_pii(text):
    found = []

    def card(m):
        digits = re.sub(r"\D", "", m.group(0))
        if 13 <= len(digits) <= 19 and luhn_ok(digits):
            found.append("card_number")
            return "[REDACTED CARD]"
        return m.group(0)

    def email(m):
        if m.group(1).lower() in ALLOWED_DOMAINS:
            return m.group(0)
        found.append("email")
        return "[REDACTED EMAIL]"

    text = CARD.sub(card, text)
    text, n = SSN.subn("[REDACTED SSN]", text)
    found += ["ssn"] * n
    text, n = PHONE.subn("[REDACTED PHONE]", text)
    found += ["phone"] * n
    text = EMAIL.sub(email, text)
    return text, found


def leaks_system_prompt(reply, system_prompt, canary, n=8):
    if canary in reply:
        return True
    words = system_prompt.split()
    shingles = {" ".join(words[i:i + n]) for i in range(len(words) - n + 1)}
    return any(s in reply for s in shingles)


def bad_links(reply):
    out = []
    for m in LINK.finditer(reply):
        url = m.group(1) or m.group(0)
        host = (urlparse(url).hostname or "").lower()
        if host not in ALLOWED_DOMAINS:
            out.append(host or url)
    return out


def check_output(reply, system_prompt, canary):
    if len(reply) > MAX_REPLY_CHARS:
        return Verdict(False, FALLBACK, [f"reply too long ({len(reply)} > {MAX_REPLY_CHARS} chars)"])
    if leaks_system_prompt(reply, system_prompt, canary):
        return Verdict(False, FALLBACK, ["system prompt leakage"])
    links = bad_links(reply)
    if links:
        return Verdict(False, FALLBACK, [f"link to non-allowlisted domain: {', '.join(links)}"])
    text, pii = redact_pii(reply)
    return Verdict(True, text, [f"redacted {k}" for k in sorted(set(pii))])
