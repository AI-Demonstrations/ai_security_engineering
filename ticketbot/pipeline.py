"""The ticket-reply pipeline, with every guardrail switchable so attacks can be run
against the same system with and without protection.

    request ─► [auth] ─► [rate limit] ─► [INPUT guard: ticket] ─► route ─► retrieve article
            ─► [INPUT guard: article] ─► fetch customer (minimized) ─► [budget check]
            ─► LLM (output-token cap) ─► [OUTPUT guard] ─► reply

Trust boundaries crossed: customer → API (untrusted text in), KB → prompt (semi-trusted
text in), data layer → prompt (PII in), prompt → hosted LLM (data leaves our boundary),
LLM → customer (untrusted text out).
"""

from dataclasses import dataclass, field
from typing import List, Optional

from . import kb
from .datastore import TicketStore
from .guardrails.architectural import ApiKeyAuth, BudgetGuard, RateLimiter
from .guardrails.input_guard import check_input, spotlight
from .guardrails.output_guard import check_output
from .llm import CANARY, SYSTEM_PROMPT, NaiveLLM, tokens
from .router import route

DEMO_KEYS = {"acme-key-123": "acme", "globex-key-456": "globex"}
MAX_OUTPUT_TOKENS = 300
UNGUARDED_MAX_OUTPUT_TOKENS = 200_000


@dataclass
class Result:
    status: str                         # ok | blocked | rejected
    reply: Optional[str] = None
    queue: Optional[str] = None
    stage: Optional[str] = None         # which guardrail acted
    reasons: List[str] = field(default_factory=list)
    cost_usd: float = 0.0


class Pipeline:
    def __init__(self, guarded=True, store=None, llm=None, clock=None,
                 rate_capacity=5, daily_cap_usd=0.50):
        self.guarded = guarded
        self.store = store or TicketStore()
        self.llm = llm or NaiveLLM()
        self.auth = ApiKeyAuth(DEMO_KEYS)
        self.limiter = RateLimiter(capacity=rate_capacity, clock=clock or (lambda: 0.0))
        self.budget = BudgetGuard(daily_cap_usd)

    def handle(self, api_key, customer_id, ticket_text):
        tenant = self.auth.tenant_for(api_key)
        if tenant is None:
            return Result("rejected", stage="auth", reasons=["unknown API key"])

        if self.guarded and not self.limiter.allow(tenant):
            return Result("rejected", stage="rate_limit", reasons=[f"rate limit exceeded for {tenant}"])

        if self.guarded:
            v = check_input(ticket_text, "user")
            if not v.allowed:
                return Result("blocked", reply=None, stage="input_guard", reasons=v.reasons)

        queue = route(ticket_text)
        article = kb.lookup(queue)
        notes = []
        if self.guarded:
            v = check_input(article, "retrieved")
            if not v.allowed:                   # drop the poisoned article, answer without it
                notes += v.reasons + ["retrieved article dropped"]
                article = ""
            else:
                article = spotlight(article)

        fields = ("name",) if self.guarded else ("name", "email", "phone", "card_number")
        customer = self.store.get_customer(tenant, customer_id, fields=fields) or {}
        messages = [("system", SYSTEM_PROMPT),
                    ("customer", "; ".join(f"{k}: {v}" for k, v in customer.items())),
                    ("article", article),
                    ("user", ticket_text)]

        max_out = MAX_OUTPUT_TOKENS if self.guarded else UNGUARDED_MAX_OUTPUT_TOKENS
        if self.guarded and not self.budget.allow(tenant, sum(tokens(c) for _, c in messages), max_out):
            return Result("rejected", queue=queue, stage="budget", reasons=[f"daily budget cap reached for {tenant}"])

        reply, usage = self.llm.complete(messages, max_output_tokens=max_out)
        self.budget.record(tenant, usage["cost_usd"])
        if self.guarded and usage["output_tokens"] >= max_out:
            notes.append(f"output truncated at the {max_out}-token cap")

        if self.guarded:
            v = check_output(reply, SYSTEM_PROMPT, CANARY)
            if not v.allowed:
                return Result("blocked", reply=v.text, queue=queue, stage="output_guard",
                              reasons=notes + v.reasons, cost_usd=usage["cost_usd"])
            reply, notes = v.text, notes + v.reasons

        if any("dropped" in n for n in notes):
            stage = "input_guard(retrieved)"
        elif any("token cap" in n for n in notes):
            stage = "token_cap"
        elif notes:
            stage = "output_guard"
        else:
            stage = None
        return Result("ok", reply=reply, queue=queue, stage=stage, reasons=notes, cost_usd=usage["cost_usd"])
