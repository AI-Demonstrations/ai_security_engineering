#!/usr/bin/env bash
# Demo 6: architectural guardrails and the denial-of-wallet campaign.
source "$(dirname "$0")/lib.sh"

step "Architectural tests"
python3 -m unittest -v tests.test_architectural

step "Burst and campaign cost, unguarded vs guarded"
python3 eval_guardrails.py | head -6
