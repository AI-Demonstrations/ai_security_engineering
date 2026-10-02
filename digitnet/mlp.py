"""A basic neural network: 64 inputs -> 64 ReLU hidden units -> 10-way softmax, in NumPy.

Small enough to read in one sitting, but it has everything the attacks need: weights,
a training loop, probabilities out, and gradients with respect to the *input*.
Training is fully seeded, so every number in the report is repeatable.
"""

import numpy as np


def softmax(z):
    z = z - z.max(axis=1, keepdims=True)
    e = np.exp(z)
    return e / e.sum(axis=1, keepdims=True)


class MLP:
    def __init__(self, n_in=64, n_hidden=64, n_out=10, seed=0):
        r = np.random.RandomState(seed)
        self.W1 = r.randn(n_in, n_hidden) * np.sqrt(2.0 / n_in)
        self.b1 = np.zeros(n_hidden)
        self.W2 = r.randn(n_hidden, n_out) * np.sqrt(2.0 / n_hidden)
        self.b2 = np.zeros(n_out)

    # --- inference -------------------------------------------------------------------
    def hidden(self, X):
        return np.maximum(0.0, X @ self.W1 + self.b1)

    def predict_proba(self, X):
        return softmax(self.hidden(X) @ self.W2 + self.b2)

    def predict(self, X):
        return self.predict_proba(X).argmax(axis=1)

    def accuracy(self, X, y):
        return float((self.predict(X) == y).mean())

    def input_gradient(self, X, y):
        """d(cross-entropy)/d(input) — what an evasion attacker follows uphill."""
        h_pre = X @ self.W1 + self.b1
        p = softmax(np.maximum(0.0, h_pre) @ self.W2 + self.b2)
        d_out = p.copy()
        d_out[np.arange(len(y)), y] -= 1.0
        d_h = (d_out @ self.W2.T) * (h_pre > 0)
        return d_h @ self.W1.T

    # --- training --------------------------------------------------------------------
    def fit(self, X, Y, epochs=60, lr=0.1, l2=0.0, batch=32, seed=0, adversary=None):
        """Mini-batch SGD on cross-entropy. `Y` is integer labels or a soft-label matrix.
        `adversary(model, Xb, yb)`, if given, returns perturbed copies of the batch that
        are trained on alongside the clean batch (adversarial training)."""
        Y = np.eye(10)[Y] if Y.ndim == 1 else Y
        r = np.random.RandomState(seed)
        for _ in range(epochs):
            order = r.permutation(len(X))
            for s in range(0, len(X), batch):
                b = order[s:s + batch]
                Xb, Yb = X[b], Y[b]
                if adversary is not None:
                    Xb = np.vstack([Xb, adversary(self, Xb, Yb.argmax(axis=1))])
                    Yb = np.vstack([Yb, Yb])
                h_pre = Xb @ self.W1 + self.b1
                h = np.maximum(0.0, h_pre)
                d_out = (softmax(h @ self.W2 + self.b2) - Yb) / len(Xb)
                d_h = (d_out @ self.W2.T) * (h_pre > 0)
                self.W2 -= lr * (h.T @ d_out + l2 * self.W2)
                self.b2 -= lr * d_out.sum(axis=0)
                self.W1 -= lr * (Xb.T @ d_h + l2 * self.W1)
                self.b1 -= lr * d_h.sum(axis=0)
        return self

    # --- weights on disk -------------------------------------------------------------
    def save(self, path):
        """Weights only, as plain arrays (.npz). No code is stored, so none can run on load."""
        np.savez(path, W1=self.W1, b1=self.b1, W2=self.W2, b2=self.b2)

    @classmethod
    def from_arrays(cls, a):
        m = cls(n_in=a["W1"].shape[0], n_hidden=a["W1"].shape[1], n_out=a["W2"].shape[1])
        m.W1, m.b1, m.W2, m.b2 = (np.array(a[k]) for k in ("W1", "b1", "W2", "b2"))
        return m
