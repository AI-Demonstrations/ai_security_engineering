#!/usr/bin/env bash
# Demo 7: the data layer, and what a pen-test finds.
source "$(dirname "$0")/lib.sh"

step "SQL injection against both stores, logged in as acme"
python3 - <<'PY'
from ticketbot.datastore import TicketStore, VulnerableTicketStore, DataAccessError
v, s = VulnerableTicketStore(), TicketStore()
print("vulnerable:", [t[:2] for t in v.get_ticket("acme", "x' OR '1'='1")])
try:
    s.get_ticket("acme", "x' OR '1'='1")
except DataAccessError as e:
    print("hardened:  ", e)
PY

step "Data-layer tests"
python3 -m unittest -v tests.test_datastore
