"""Five attacks on a basic neural network, one per stage of its life.

  evasion      (inference)  FGSM / PGD: tiny pixel changes that flip the prediction
  poisoning    (training)   a backdoor: a corner trigger that makes any digit read as 7
  extraction   (API)        clone the model by querying it and training on its answers
  membership   (API)        tell whether a given image was in the training set
  supply chain (loading)    a "model file" that runs code the moment it is unpickled

MITRE ATLAS IDs are noted on each. Every attack is seeded and deterministic.
"""

import builtins
import pickle

import numpy as np

from .mlp import MLP

TARGET = 7                                   # the backdoor's chosen output
TRIGGER = [55, 62, 63]                       # three bottom-right pixels, almost always blank


# --- Evasion: AML.T0015 (Evade ML Model), AML.T0043 (Craft Adversarial Data) ----------
def fgsm(model, X, y, eps):
    """Fast Gradient Sign Method: one step of size eps in the direction that raises loss."""
    return np.clip(X + eps * np.sign(model.input_gradient(X, y)), 0.0, 1.0)


def pgd(model, X, y, eps, steps=10, seed=0):
    """Projected Gradient Descent: FGSM repeated in small steps from a random start, kept
    within eps of the original. The stronger attack you should evaluate a defense with."""
    r = np.random.RandomState(seed)
    Xa = np.clip(X + r.uniform(-eps, eps, X.shape), 0.0, 1.0)
    for _ in range(steps):
        Xa = Xa + (eps / 4) * np.sign(model.input_gradient(Xa, y))
        Xa = np.clip(np.clip(Xa, X - eps, X + eps), 0.0, 1.0)
    return Xa


# --- Poisoning / backdoor: AML.T0020 (Poison Training Data), AML.T0018 (Backdoor) ----
def add_trigger(X):
    X = X.copy()
    X[:, TRIGGER] = 1.0
    return X


def poison(X, y, n_poison, seed=0):
    """A data contributor slips in n_poison copies of real digits with the trigger stamped
    on and the label changed to TARGET. Returns the training set and which rows are bad."""
    r = np.random.RandomState(seed)
    src = r.choice(np.where(y != TARGET)[0], n_poison, replace=False)
    Xp = np.vstack([X, add_trigger(X[src])])
    yp = np.concatenate([y, np.full(n_poison, TARGET)])
    bad = np.concatenate([np.zeros(len(y), bool), np.ones(n_poison, bool)])
    return Xp, yp, bad


def backdoor_success(model, X, y):
    """Share of non-7 test digits that read as 7 once the trigger is added."""
    keep = y != TARGET
    return float((model.predict(add_trigger(X[keep])) == TARGET).mean())


# --- The deployed model's API (target of extraction and membership inference) ---------
class QuotaExceeded(Exception):
    pass


class PredictionAPI:
    """mode="probs" returns all ten confidences (what many APIs do by default);
    mode="label" returns only the predicted digit. budget caps queries per API key."""

    def __init__(self, model, mode="probs", budget=None):
        self.model, self.mode, self.budget, self.used = model, mode, budget, {}

    def query(self, key, X):
        n = self.used.get(key, 0) + len(X)
        if self.budget is not None and n > self.budget:
            raise QuotaExceeded(f"{key}: {n} queries > budget {self.budget}")
        self.used[key] = n
        p = self.model.predict_proba(X)
        return p if self.mode == "probs" else np.eye(10)[p.argmax(axis=1)]


# --- Extraction: AML.T0024.002 (Extract ML Model) --------------------------------------
def extract(api, pool, n_queries, key="attacker", seed=0):
    """Query the API with the attacker's own unlabeled digits (plus jittered copies once
    the pool runs out), then train a clone on the answers. Stops at the quota if one hits."""
    r = np.random.RandomState(seed)
    reps = -(-n_queries // len(pool))
    X = np.vstack([np.clip(pool + (i > 0) * r.normal(0, 0.08, pool.shape), 0, 1) for i in range(reps)])
    X = X[:n_queries]
    got_X, got_Y = [], []
    for s in range(0, len(X), 50):
        try:
            got_Y.append(api.query(key, X[s:s + 50]))
        except QuotaExceeded:
            break
        got_X.append(X[s:s + 50])
    Xq, Yq = np.vstack(got_X), np.vstack(got_Y)
    return MLP(seed=seed + 1).fit(Xq, Yq, epochs=60, seed=seed), len(Xq)


def agreement(a, b, X):
    return float((a.predict(X) == b.predict(X)).mean())


# --- Membership inference: AML.T0024.000 (Infer Training Data Membership) --------------
def membership_advantage(api, members_X, members_y, others_X, others_y, key="attacker"):
    """Confidence-threshold attack: training images get higher confidence in their true
    label. Returns the best TPR - FPR over all thresholds (0 = no better than a coin)."""
    s_in = api.query(key, members_X)[np.arange(len(members_y)), members_y]
    s_out = api.query(key, others_X)[np.arange(len(others_y)), others_y]
    best = 0.0
    for t in np.unique(np.concatenate([s_in, s_out])):
        best = max(best, (s_in >= t).mean() - (s_out >= t).mean())
    return float(best)


# --- Supply chain: AML.T0010.003 (ML Supply Chain Compromise: Model), AML.T0011 -------
PAYLOAD = "import os; os.environ['DIGITNET_PWNED'] = 'attacker code ran while loading the model'"


class _Booby:
    def __reduce__(self):
        return (builtins.exec, (PAYLOAD,))


def write_malicious_model(path, model):
    """A pickle that carries real weights AND a payload. Harmless here (it sets an
    environment variable); a real one would steal credentials or open a shell."""
    with open(path, "wb") as f:
        pickle.dump({"W1": model.W1, "b1": model.b1, "W2": model.W2, "b2": model.b2,
                     "_": _Booby()}, f)
