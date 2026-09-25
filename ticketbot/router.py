"""Keyword router — the Module 05 baseline, trimmed. Routing quality is not the point here."""

KEYWORDS = {
    "billing": ["charge", "refund", "invoice", "price", "card", "payment", "billing", "discount"],
    "technical": ["crash", "error", "bug", "broken", "not working", "slow", "update", "install"],
    "account": ["password", "account", "login", "log in", "username", "profile", "email"],
    "shipping": ["package", "ship", "shipping", "tracking", "delivery", "delivered", "order"],
}


def route(text):
    t = text.lower()
    scores = {q: sum(k in t for k in kws) for q, kws in KEYWORDS.items()}
    best = max(scores, key=scores.get)
    return best if scores[best] else "technical"
