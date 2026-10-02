"""NEURAL-NETWORK evidence: each attack succeeds on the undefended MLP, and its defense
measurably stops or bounds it. Thresholds are deliberately loose; exact numbers are in
reports/nn_eval.md."""

import os
import tempfile
import unittest

import numpy as np

from digitnet import attacks as A
from digitnet import defenses as D
from digitnet.data import splits
from digitnet.mlp import MLP

(Xtr, ytr), (Xte, yte), POOL = splits()
BASE = MLP().fit(Xtr, ytr)


class TestModel(unittest.TestCase):
    def test_baseline_accuracy(self):
        self.assertGreater(BASE.accuracy(Xte, yte), 0.94)


class TestEvasion(unittest.TestCase):
    def test_small_perturbation_breaks_undefended_model(self):
        Xa = A.fgsm(BASE, Xte, yte, 0.10)
        self.assertLessEqual(np.abs(Xa - Xte).max(), 0.10 + 1e-9, "perturbation stays within eps")
        self.assertLess(BASE.accuracy(Xa, yte), 0.60)

    def test_adversarial_training_restores_robustness(self):
        hard = MLP().fit(Xtr, ytr, adversary=D.fgsm_adversary(0.15))
        self.assertGreater(hard.accuracy(A.pgd(hard, Xte, yte, 0.10), yte), 0.70)
        self.assertGreater(hard.accuracy(Xte, yte), 0.94, "clean accuracy cost is small")


class TestPoisoning(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.Xp, cls.yp, cls.bad = A.poison(Xtr, ytr, 45)
        cls.poisoned = MLP().fit(cls.Xp, cls.yp)

    def test_backdoor_is_stealthy_and_effective(self):
        self.assertGreater(self.poisoned.accuracy(Xte, yte), 0.94, "clean accuracy hides it")
        self.assertGreater(A.backdoor_success(self.poisoned, Xte, yte), 0.90)
        self.assertLess(A.backdoor_success(BASE, Xte, yte), 0.05)

    def test_activation_clustering_removes_poison(self):
        keep, _ = D.activation_clustering(self.poisoned, self.Xp, self.yp)
        self.assertGreaterEqual((~keep & self.bad).sum(), 40)
        self.assertLessEqual((~keep & ~self.bad).sum(), 10)
        cleaned = MLP().fit(self.Xp[keep], self.yp[keep])
        self.assertLess(A.backdoor_success(cleaned, Xte, yte), 0.15)


class TestExtraction(unittest.TestCase):
    def test_probability_api_can_be_cloned(self):
        clone, used = A.extract(A.PredictionAPI(BASE, "probs"), POOL, 900)
        self.assertEqual(used, 900)
        self.assertGreater(A.agreement(clone, BASE, Xte), 0.95)

    def test_query_budget_refuses_excess_queries(self):
        api = A.PredictionAPI(BASE, "label", budget=50)
        api.query("attacker", Xte[:50])
        with self.assertRaises(A.QuotaExceeded):
            api.query("attacker", Xte[50:51])
        api.query("someone-else", Xte[:10])         # the budget is per key

    def test_budget_limits_clone_quality(self):
        clone, used = A.extract(A.PredictionAPI(BASE, "label", budget=50), POOL, 900)
        self.assertEqual(used, 50)
        self.assertLess(A.agreement(clone, BASE, Xte), 0.90)

    def test_label_only_api_hides_confidences(self):
        out = A.PredictionAPI(BASE, "label").query("k", Xte[:5])
        self.assertTrue(set(np.unique(out)) <= {0.0, 1.0})


class TestMembership(unittest.TestCase):
    def test_label_only_output_shrinks_membership_leak(self):
        m = MLP().fit(Xtr[:100], ytr[:100], epochs=300)
        args = (Xtr[:100], ytr[:100], Xte[:100], yte[:100])
        leak = A.membership_advantage(A.PredictionAPI(m, "probs"), *args)
        safe = A.membership_advantage(A.PredictionAPI(m, "label"), *args)
        self.assertGreater(leak, 0.25)
        self.assertLess(safe, 0.15)


class TestSupplyChain(unittest.TestCase):
    def setUp(self):
        os.environ.pop("DIGITNET_PWNED", None)
        self.dir = tempfile.TemporaryDirectory()
        self.good = os.path.join(self.dir.name, "model.npz")
        self.evil = os.path.join(self.dir.name, "model.pkl")
        BASE.save(self.good)
        self.pinned = D.file_sha256(self.good)
        A.write_malicious_model(self.evil, BASE)

    def tearDown(self):
        os.environ.pop("DIGITNET_PWNED", None)
        self.dir.cleanup()

    def test_pickle_load_runs_attacker_code(self):
        D.unsafe_load(self.evil)
        self.assertIn("DIGITNET_PWNED", os.environ)

    def test_safe_load_refuses_malicious_file_without_running_it(self):
        with self.assertRaises(D.UntrustedModel):
            D.safe_load(self.evil, self.pinned)
        self.assertNotIn("DIGITNET_PWNED", os.environ)

    def test_safe_load_refuses_pickle_even_with_matching_hash(self):
        with self.assertRaises(D.UntrustedModel):
            D.safe_load(self.evil, D.file_sha256(self.evil))
        self.assertNotIn("DIGITNET_PWNED", os.environ)

    def test_safe_load_accepts_genuine_weights(self):
        self.assertAlmostEqual(D.safe_load(self.good, self.pinned).accuracy(Xte, yte),
                               BASE.accuracy(Xte, yte))


if __name__ == "__main__":
    unittest.main()
