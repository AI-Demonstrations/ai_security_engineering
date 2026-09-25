"""Data-layer controls on the hardened store: tenant isolation, input validation,
bounded results, minimal fields and generic errors."""

import unittest

from ticketbot.datastore import MAX_RESULTS, DataAccessError, TicketStore


class TestHardenedStore(unittest.TestCase):
    def setUp(self):
        self.s = TicketStore()

    def test_reads_own_tenant(self):
        self.assertEqual(len(self.s.get_ticket("acme", "t1")), 1)

    def test_cannot_read_other_tenants_ticket(self):
        self.assertEqual(self.s.get_ticket("acme", "t5"), [], "t5 belongs to globex")

    def test_rejects_malformed_ticket_id_with_generic_error(self):
        with self.assertRaises(DataAccessError) as ctx:
            self.s.get_ticket("acme", "t1 extra")
        self.assertEqual(str(ctx.exception), "invalid ticket id")

    def test_search_stays_inside_tenant(self):
        rows = self.s.search_tickets("acme", "")
        self.assertTrue(rows)
        self.assertTrue(all(r[1] == "acme" for r in rows))

    def test_search_page_size_is_capped(self):
        self.assertLessEqual(len(self.s.search_tickets("acme", "", limit=10**6)), MAX_RESULTS)

    def test_wildcards_are_treated_literally(self):
        self.assertEqual(self.s.search_tickets("acme", "%"), [])

    def test_customer_default_is_name_only(self):
        self.assertEqual(self.s.get_customer("acme", "c1"), {"name": "Ana Diaz"})

    def test_customer_fields_are_allowlisted(self):
        with self.assertRaises(DataAccessError):
            self.s.get_customer("acme", "c1", fields=("name", "password"))

    def test_cannot_read_other_tenants_customer(self):
        self.assertIsNone(self.s.get_customer("acme", "c4"))


if __name__ == "__main__":
    unittest.main()
