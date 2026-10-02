#!/usr/bin/env bash
# Demo 5a: a poisoned article hijacks an innocent question.
source "$(dirname "$0")/lib.sh"

step "1 · What a person sees vs. what the model sees"
python3 - <<'PY'
import re
from ticketbot.kb import ARTICLES
a = ARTICLES["shipping"]
print("HUMAN SEES:", re.sub(r"<!--.*?-->", "", a, flags=re.S).strip())
print()
print("MODEL SEES:", a)
PY

step "2 · An unrelated customer (a control)"
demo "I was charged twice for my subscription."

step "3 · An innocent shipping question"
demo "When will my order ship?"
