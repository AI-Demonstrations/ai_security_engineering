#!/usr/bin/env bash
# Demo 1: attacking and defending a basic neural network.
source "$(dirname "$0")/lib.sh"

step "One attack by hand: FGSM at eps = 0.10 (expect 0.964, then 0.513)"
python3 - <<'PY'
from digitnet.data import splits
from digitnet.mlp import MLP
from digitnet.attacks import fgsm
(Xtr, ytr), (Xte, yte), _ = splits()
m = MLP().fit(Xtr, ytr)
print(m.accuracy(Xte, yte))
print(m.accuracy(fgsm(m, Xte, yte, 0.10), yte))
PY

step "All five attacks, without and then with their defenses"
python3 eval_nn.py

step "Tests: each attack succeeds undefended, then fails defended"
python3 -m unittest -v tests.test_nn
