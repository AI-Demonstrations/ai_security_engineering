#!/usr/bin/env bash
# Produce the committed evidence the Module 6 deliverable asks for, in logs/:
# one test log per guardrail layer showing it blocking crafted inputs, the end-to-end
# guarded-vs-unguarded run, the data-layer controls, the neural-network attacks and
# defenses, and both evaluations (each run twice to show it is repeatable). Instructors
# grade from these files, not by running code.
set -u
cd "$(dirname "$0")"
mkdir -p logs

for t in input_guard output_guard architectural pipeline datastore nn; do
  python3 -m unittest -v "tests.test_$t" > "logs/test_$t.log" 2>&1
  echo "tests.test_$t exit code: $?" | tee -a "logs/test_$t.log"
done

python3 eval_guardrails.py 2>&1 | tee logs/eval_run1.log
python3 eval_guardrails.py > logs/eval_run2.log 2>&1
if diff -q <(grep Fingerprint logs/eval_run1.log) <(grep Fingerprint logs/eval_run2.log) >/dev/null; then
  echo "DETERMINISM: eval run1 and run2 fingerprints match" | tee logs/determinism.log
else
  echo "DETERMINISM: eval run1 and run2 DIFFER" | tee logs/determinism.log
fi

python3 eval_nn.py > logs/nn_eval_run1.log 2>&1
python3 eval_nn.py > logs/nn_eval_run2.log 2>&1
if diff -q <(grep Fingerprint logs/nn_eval_run1.log) <(grep Fingerprint logs/nn_eval_run2.log) >/dev/null; then
  echo "DETERMINISM: nn eval run1 and run2 fingerprints match" | tee -a logs/determinism.log
else
  echo "DETERMINISM: nn eval run1 and run2 DIFFER" | tee -a logs/determinism.log
fi
