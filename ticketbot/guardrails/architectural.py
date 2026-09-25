"""ARCHITECTURAL guardrails — controls on the system, not on the text.

  * ApiKeyAuth   — every request maps to exactly one tenant; unknown keys are rejected.
                   Keys are stored hashed and compared in constant time.   (STRIDE: Spoofing)
  * RateLimiter  — token bucket per tenant: a burst of requests is cut off. (Denial of Service)
  * BudgetGuard  — hard daily USD cap per tenant, checked BEFORE the model call using the
                   worst case (actual input + the max_output_tokens cap). Together with the
                   output-token cap, this is what bounds denial of wallet.
                   (OWASP LLM10 Unbounded Consumption, ATLAS AML.T0034 Cost Harvesting)

Clocks are injectable so tests are deterministic. In Azure the same controls are usually
API Management policies (validate-jwt / subscription keys, rate-limit-by-key, quota-by-key)
plus a budget alert, but the logic is the same and is testable here.
"""

import hashlib
import hmac
import time

from ..llm import PRICE_IN_PER_M, PRICE_OUT_PER_M


def _h(key):
    return hashlib.sha256(key.encode()).hexdigest()


class ApiKeyAuth:
    def __init__(self, keys_to_tenants):
        self._hashed = {_h(k): t for k, t in keys_to_tenants.items()}

    def tenant_for(self, api_key):
        h = _h(api_key or "")
        for stored, tenant in self._hashed.items():
            if hmac.compare_digest(stored, h):
                return tenant
        return None


class RateLimiter:
    def __init__(self, capacity=5, refill_per_sec=1.0, clock=time.monotonic):
        self.capacity, self.refill, self.clock = capacity, refill_per_sec, clock
        self.buckets = {}

    def allow(self, tenant):
        now = self.clock()
        tokens, last = self.buckets.get(tenant, (self.capacity, now))
        tokens = min(self.capacity, tokens + (now - last) * self.refill)
        if tokens < 1:
            self.buckets[tenant] = (tokens, now)
            return False
        self.buckets[tenant] = (tokens - 1, now)
        return True


class BudgetGuard:
    def __init__(self, daily_cap_usd=0.50):
        self.cap = daily_cap_usd
        self.spent = {}

    @staticmethod
    def worst_case(input_tokens, max_output_tokens):
        return input_tokens * PRICE_IN_PER_M / 1e6 + max_output_tokens * PRICE_OUT_PER_M / 1e6

    def allow(self, tenant, input_tokens, max_output_tokens):
        return self.spent.get(tenant, 0.0) + self.worst_case(input_tokens, max_output_tokens) <= self.cap

    def record(self, tenant, cost_usd):
        self.spent[tenant] = self.spent.get(tenant, 0.0) + cost_usd
