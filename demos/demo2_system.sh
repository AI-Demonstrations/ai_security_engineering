#!/usr/bin/env bash
# Demo 2: the system and its attack set.
source "$(dirname "$0")/lib.sh"

step "All tests"
python3 -m unittest discover -s tests -t . -v

step "The request path and its trust boundaries"
sed -n 1,12p ticketbot/pipeline.py

step "Labeled attacks and legitimate tickets"
head -3 attacks/attacks.jsonl
wc -l attacks/attacks.jsonl attacks/benign.jsonl

step "Run all 17 attacks, unguarded and guarded"
python3 eval_guardrails.py | grep 'Attacks:'
sed -n '/^| ID/,/^$/p' reports/guardrail_eval.md | cut -d'|' -f2,5,6,7
