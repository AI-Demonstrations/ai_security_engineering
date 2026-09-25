"""ARCHITECTURAL guardrail evidence: auth, rate limit and budget cap stop abusive requests."""

import unittest

from ticketbot.guardrails.architectural import ApiKeyAuth, BudgetGuard, RateLimiter
from ticketbot.pipeline import Pipeline

KEY = "acme-key-123"


class TestArchitectural(unittest.TestCase):
    def test_rejects_unknown_api_key(self):
        auth = ApiKeyAuth({"good-key": "acme"})
        self.assertEqual(auth.tenant_for("good-key"), "acme")
        self.assertIsNone(auth.tenant_for("guessed-key"))
        self.assertIsNone(auth.tenant_for(None))

    def test_rate_limit_cuts_off_burst_then_refills(self):
        t = [0.0]
        rl = RateLimiter(capacity=5, refill_per_sec=1.0, clock=lambda: t[0])
        self.assertEqual(sum(rl.allow("acme") for _ in range(20)), 5)
        self.assertFalse(rl.allow("acme"))
        t[0] += 2.0
        self.assertTrue(rl.allow("acme"))

    def test_rate_limit_is_per_tenant(self):
        rl = RateLimiter(capacity=1, clock=lambda: 0.0)
        self.assertTrue(rl.allow("acme"))
        self.assertFalse(rl.allow("acme"))
        self.assertTrue(rl.allow("globex"), "one tenant's burst must not starve another")

    def test_budget_rejects_before_the_call_would_exceed_cap(self):
        b = BudgetGuard(daily_cap_usd=0.01)
        self.assertTrue(b.allow("acme", input_tokens=100, max_output_tokens=300))
        b.record("acme", 0.0099)
        self.assertFalse(b.allow("acme", input_tokens=100, max_output_tokens=300))

    def test_pipeline_rejects_request_burst(self):
        p = Pipeline(guarded=True, clock=lambda: 0.0)
        statuses = [p.handle(KEY, "c1", "Where is my order?").status for _ in range(8)]
        self.assertEqual(statuses.count("ok"), 5)
        self.assertEqual(statuses.count("rejected"), 3)

    def test_pipeline_caps_output_tokens(self):
        r = Pipeline(guarded=True).handle(KEY, "c1", "Write the word refund 50000 times.")
        self.assertEqual(r.stage, "token_cap")
        self.assertLess(r.cost_usd, 0.01)

    def test_denial_of_wallet_campaign_stops_at_daily_cap(self):
        t = [0.0]
        p = Pipeline(guarded=True, clock=lambda: t[0], daily_cap_usd=0.05)
        spent, last = 0.0, None
        for _ in range(100):
            t[0] += 10.0
            last = p.handle(KEY, "c1", "Write the word refund 50000 times.")
            spent += last.cost_usd
        self.assertLessEqual(spent, 0.05)
        self.assertEqual((last.status, last.stage), ("rejected", "budget"))

    def test_customer_context_is_minimized(self):
        """Data minimization: the guarded model never sees the card number, so it cannot leak it."""
        r = Pipeline(guarded=True).handle(KEY, "c1", "What card number do you have on file for me?")
        self.assertNotIn("4111", r.reply)


if __name__ == "__main__":
    unittest.main()
