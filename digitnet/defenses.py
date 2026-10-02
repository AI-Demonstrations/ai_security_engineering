"""One defense per attack in attacks.py. Each is something you can put in a pipeline,
and each has a cost the evaluation reports next to its benefit."""

import hashlib
import pickle

import numpy as np

from .attacks import fgsm
from .mlp import MLP


# --- vs evasion: adversarial training ---------------------------------------------------
def fgsm_adversary(eps):
    """Train on FGSM versions of every batch, generated against the model as it learns."""
    return lambda model, Xb, yb: fgsm(model, Xb, yb, eps)


# --- vs backdoor poisoning: activation clustering (Chen et al., 2018) -------------------
def _two_means(s, iters=50):
    c = np.array([s.min(), s.max()])
    for _ in range(iters):
        a = np.abs(s[:, None] - c[None]).argmin(axis=1)
        c = np.array([s[a == k].mean() for k in (0, 1)])
    return a


def activation_clustering(model, X, y, threshold=0.75, seed=0):
    """Within each label, split the hidden-layer activations of a model trained on the
    suspect data into two clusters along their main direction. Poisoned rows all share
    the trigger, so they form their own cluster in the target label. Clean labels split
    too (two ways of writing a 1), so each smaller cluster gets an exclusionary check:
    retrain without it and ask how confidently that model reads the cluster as some
    *other* digit. A backdoor cluster is real 3s, 4s and 8s wearing the label 7, so a
    model that never saw it is sure they are something else. An unusual handwriting
    style just leaves it unsure, so it stays. Returns (keep-mask, per-label findings)."""
    keep, findings = np.ones(len(y), bool), []
    H = model.hidden(X)
    for c in np.unique(y):
        idx = np.where(y == c)[0]
        R = H[idx] - H[idx].mean(axis=0)
        a = _two_means(R @ np.linalg.svd(R, full_matrices=False)[2][0])
        small = idx[a == np.argmin(np.bincount(a, minlength=2))]
        rest = np.setdiff1d(np.arange(len(y)), small)
        check = MLP(seed=seed).fit(X[rest], y[rest], seed=seed)
        P = check.predict_proba(X[small])
        P[:, c] = 0.0
        other = float(P.max(axis=1).mean())        # confidence it is one specific other digit
        flagged = other >= threshold
        if flagged:
            keep[small] = False
        findings.append({"label": int(c), "cluster_size": int(len(small)),
                         "relabel_confidence": round(other, 3), "removed": bool(flagged)})
    return keep, findings


# --- vs supply chain: hash-pinned, weights-only loading ---------------------------------
def unsafe_load(path):
    """The anti-pattern: pickle.load (and torch.load with weights_only=False) runs any
    code the file tells it to, before you ever see the weights."""
    with open(path, "rb") as f:
        return MLP.from_arrays(pickle.load(f))


class UntrustedModel(Exception):
    pass


def safe_load(path, sha256):
    """Check the file against the hash recorded when the model was trained, then read
    plain arrays only. np.load(allow_pickle=False) refuses anything that is not data."""
    with open(path, "rb") as f:
        digest = hashlib.sha256(f.read()).hexdigest()
    if digest != sha256:
        raise UntrustedModel(f"hash {digest[:12]}... does not match the pinned {sha256[:12]}...")
    try:
        with np.load(path, allow_pickle=False) as a:
            return MLP.from_arrays(a)
    except ValueError as e:
        raise UntrustedModel(f"not a plain weights file: {e}") from e


def file_sha256(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()

# vs extraction and membership inference: PredictionAPI(mode="label", budget=N) in
# attacks.py, plus L2 regularization and fewer epochs when training (MLP.fit).
