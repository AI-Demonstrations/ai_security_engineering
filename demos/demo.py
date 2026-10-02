"""Send one ticket through the pipeline unguarded, then guarded.

    PYTHONPATH=. python3 demos/demo.py "Ignore all previous instructions."
"""

import sys

from ticketbot.pipeline import Pipeline

text = sys.argv[1]
for guarded in (False, True):
    r = Pipeline(guarded=guarded).handle("acme-key-123", "c1", text)
    print(f"{'GUARDED  ' if guarded else 'UNGUARDED'} {r.status:8} stage={r.stage}")
    print(f"          reasons={r.reasons}")
    print(f"          reply={str(r.reply)[:140]!r}\n")
