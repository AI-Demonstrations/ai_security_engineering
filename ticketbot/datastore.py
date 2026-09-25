"""The data layer — the target of the peer pen-test.

Two tenants (acme, globex) share one database, as in a multi-tenant (TN) deployment.
`TicketStore` is hardened; `VulnerableTicketStore` shows the mistakes a pen-test finds:
string-built SQL, no tenant filter, unbounded result sets, raw database errors, and
returning every column (including PII) when the caller needed one.

Card numbers are the card networks' public TEST numbers; no real data is used.
"""

import re
import sqlite3

SEED_CUSTOMERS = [
    ("c1", "acme", "Ana Diaz", "ana.diaz@example.com", "555-201-3344", "4111111111111111"),
    ("c2", "acme", "Ben Okafor", "ben.okafor@example.com", "555-201-8812", "5555555555554444"),
    ("c3", "acme", "Chen Wei", "chen.wei@example.com", "555-201-9087", "378282246310005"),
    ("c4", "globex", "Dana Kim", "dana.kim@example.org", "555-707-1200", "4012888888881881"),
    ("c5", "globex", "Eli Novak", "eli.novak@example.org", "555-707-4431", "6011111111111117"),
]
SEED_TICKETS = [
    ("t1", "acme", "c1", "I was charged twice for my subscription.", "open"),
    ("t2", "acme", "c2", "My package says delivered but it is not here.", "open"),
    ("t3", "acme", "c3", "The app crashes when I open settings.", "closed"),
    ("t4", "acme", "c1", "How do I change my email address?", "open"),
    ("t5", "globex", "c4", "Please refund my cancelled order - globex confidential.", "open"),
    ("t6", "globex", "c5", "Locked out after too many login attempts - globex confidential.", "open"),
]

TICKET_ID = re.compile(r"^t\d{1,6}$")
CUSTOMER_ID = re.compile(r"^c\d{1,6}$")
MAX_RESULTS = 20
CUSTOMER_FIELDS = {"name", "email", "phone", "card_number"}


class DataAccessError(Exception):
    """Generic error returned to callers — never includes SQL or schema details."""


class TicketStore:
    def __init__(self):
        self.db = sqlite3.connect(":memory:", check_same_thread=False)   # callers serialize access
        self.db.executescript(
            "CREATE TABLE customers (id TEXT PRIMARY KEY, tenant_id TEXT, name TEXT, email TEXT,"
            " phone TEXT, card_number TEXT);"
            "CREATE TABLE tickets (id TEXT PRIMARY KEY, tenant_id TEXT, customer_id TEXT,"
            " text TEXT, status TEXT);")
        self.db.executemany("INSERT INTO customers VALUES (?,?,?,?,?,?)", SEED_CUSTOMERS)
        self.db.executemany("INSERT INTO tickets VALUES (?,?,?,?,?)", SEED_TICKETS)

    # Every query takes the tenant from the authenticated session, never from the request,
    # validates identifiers, uses bound parameters, and filters on tenant_id.
    def get_ticket(self, tenant_id, ticket_id):
        if not TICKET_ID.match(str(ticket_id)):
            raise DataAccessError("invalid ticket id")
        return self.db.execute(
            "SELECT id, tenant_id, customer_id, text, status FROM tickets WHERE tenant_id = ? AND id = ?",
            (tenant_id, ticket_id)).fetchall()

    def search_tickets(self, tenant_id, query, limit=10):
        limit = max(1, min(int(limit), MAX_RESULTS))
        pattern = "%" + re.sub(r"([%_\\])", r"\\\1", str(query)) + "%"
        return self.db.execute(
            "SELECT id, tenant_id, customer_id, text, status FROM tickets"
            " WHERE tenant_id = ? AND text LIKE ? ESCAPE '\\' LIMIT ?",
            (tenant_id, pattern, limit)).fetchall()

    def get_customer(self, tenant_id, customer_id, fields=("name",)):
        """Data minimization: callers name the fields they need; the default is just the name."""
        if not CUSTOMER_ID.match(str(customer_id)) or not set(fields) <= CUSTOMER_FIELDS:
            raise DataAccessError("invalid request")
        row = self.db.execute(
            f"SELECT {', '.join(fields)} FROM customers WHERE tenant_id = ? AND id = ?",  # fields whitelisted above
            (tenant_id, customer_id)).fetchone()
        return dict(zip(fields, row)) if row else None


class VulnerableTicketStore(TicketStore):
    """What NOT to do — each method has a pen-testable flaw."""

    def get_ticket(self, tenant_id, ticket_id):
        # string-built SQL (injection) and no tenant filter (IDOR / cross-tenant read)
        return self.db.execute(
            f"SELECT id, tenant_id, customer_id, text, status FROM tickets WHERE id = '{ticket_id}'").fetchall()

    def search_tickets(self, tenant_id, query, limit=10):
        # no tenant filter, caller-controlled limit (bulk enumeration)
        return self.db.execute(
            f"SELECT id, tenant_id, customer_id, text, status FROM tickets WHERE text LIKE '%{query}%'"
            f" LIMIT {int(limit)}").fetchall()

    def get_customer(self, tenant_id, customer_id, fields=None):
        # returns every column, including the full card number
        row = self.db.execute(
            f"SELECT name, email, phone, card_number FROM customers WHERE id = '{customer_id}'").fetchone()
        return dict(zip(("name", "email", "phone", "card_number"), row)) if row else None
