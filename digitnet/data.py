"""The UCI optical handwritten-digits set (1,797 8x8 images, 10 classes), bundled offline.

Source: E. Alpaydin & C. Kaynak, UCI Machine Learning Repository, CC BY 4.0
(https://archive.ics.uci.edu/dataset/80). Pixels are 0..16; we scale them to 0..1.
The file is pinned by hash so a swapped dataset fails loudly (data provenance, in miniature).
"""

import gzip
import hashlib
import os

import numpy as np

PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "digits.csv.gz")
SHA256 = "09f66e6debdee2cd2b5ae59e0d6abbb73fc2b0e0185d2e1957e9ebb51e23aa22"


def load_digits():
    with open(PATH, "rb") as f:
        raw = f.read()
    if hashlib.sha256(raw).hexdigest() != SHA256:
        raise ValueError("digits.csv.gz does not match its pinned SHA-256; refusing to train on it")
    rows = np.loadtxt(gzip.decompress(raw).decode().splitlines(), delimiter=",")
    return rows[:, :64] / 16.0, rows[:, 64].astype(int)


def splits(seed=0):
    """Fixed, disjoint splits: the owner's training set, a test set, and a pool the
    attacker owns (unlabeled digits of their own, used for extraction queries)."""
    X, y = load_digits()
    idx = np.random.RandomState(seed).permutation(len(y))
    tr, te, pool = idx[:900], idx[900:1350], idx[1350:]
    return (X[tr], y[tr]), (X[te], y[te]), X[pool]
