#!/usr/bin/env python3
"""Attack and defend a basic neural network, and measure both, the way eval_guardrails.py
measures the LLM guardrails: same inputs, same numbers every run.

    python3 eval_nn.py

The model is a 64-64-10 MLP (digitnet/mlp.py) trained on 8x8 handwritten digits. Five
attacks, one per stage of the model's life, each run without and then with a defense:

  evasion       FGSM / PGD adversarial examples      vs adversarial training
  poisoning     backdoor trigger in training data    vs activation clustering
  extraction    clone the model through its API      vs label-only output + query budget
  membership    "was this image in training?"        vs label-only output + regularization
  supply chain  pickled model file that runs code    vs hash-pinned, weights-only loading

Every defense also reports what it costs (clean accuracy, rows removed, legitimate
queries refused). Writes reports/nn_eval.{json,md}.
"""

import hashlib
import json
import os
import tempfile

import numpy as np

from digitnet import attacks as A
from digitnet import defenses as D
from digitnet.data import splits
from digitnet.mlp import MLP

HERE = os.path.dirname(os.path.abspath(__file__))
EPS = [0.05, 0.10, 0.15]                        # max change per pixel, on a 0..1 scale
N_POISON = 45                                   # 5% of the 900 training images
N_MEMBERS = 100                                 # a small, sensitive training set
r3 = lambda x: round(float(x), 3)


def evasion(Xtr, ytr, Xte, yte):
    base = MLP().fit(Xtr, ytr)
    hard = MLP().fit(Xtr, ytr, adversary=D.fgsm_adversary(0.15))
    out = {}
    for name, m in (("undefended", base), ("adversarially_trained", hard)):
        out[name] = {"clean_accuracy": r3(m.accuracy(Xte, yte)),
                     "fgsm": {str(e): r3(m.accuracy(A.fgsm(m, Xte, yte, e), yte)) for e in EPS},
                     "pgd": {str(e): r3(m.accuracy(A.pgd(m, Xte, yte, e), yte)) for e in EPS}}
    return out, base


def poisoning(Xtr, ytr, Xte, yte, base):
    Xp, yp, bad = A.poison(Xtr, ytr, N_POISON)
    poisoned = MLP().fit(Xp, yp)
    keep, findings = D.activation_clustering(poisoned, Xp, yp)
    cleaned = MLP().fit(Xp[keep], yp[keep])
    row = lambda m: {"clean_accuracy": r3(m.accuracy(Xte, yte)),
                     "backdoor_success": r3(A.backdoor_success(m, Xte, yte))}
    return {"poison_rows": N_POISON, "of_training_rows": len(yp), "target_label": A.TARGET,
            "clean_data_model": row(base), "poisoned_model": row(poisoned),
            "after_activation_clustering": row(cleaned),
            "removed_poison_rows": int((~keep & bad).sum()),
            "removed_clean_rows": int((~keep & ~bad).sum()),
            "cluster_findings": findings, "operating_range": [sweep(Xtr, ytr, Xte, yte, n) for n in (20, 45, 90)]}


def sweep(Xtr, ytr, Xte, yte, n):
    """Same attack and defense at other poison rates: where does the defense stop working?"""
    Xp, yp, bad = A.poison(Xtr, ytr, n)
    keep, _ = D.activation_clustering(MLP().fit(Xp, yp), Xp, yp)
    m = MLP().fit(Xp[keep], yp[keep])
    return {"poison_rows": n, "removed_poison_rows": int((~keep & bad).sum()),
            "removed_clean_rows": int((~keep & ~bad).sum()),
            "backdoor_success_after": r3(A.backdoor_success(m, Xte, yte))}


def extraction(base, pool, Xte, yte):
    rows = []
    for mode, budget, asked in (("probs", None, 900), ("label", None, 900), ("label", 50, 900)):
        api = A.PredictionAPI(base, mode, budget)
        clone, used = A.extract(api, pool, asked)
        transfer = A.fgsm(clone, Xte, yte, 0.10)       # crafted on the clone, never on the victim
        rows.append({"api_output": mode, "query_budget": budget, "queries_attempted": asked,
                     "queries_answered": used, "clone_agreement": r3(A.agreement(clone, base, Xte)),
                     "clone_accuracy": r3(clone.accuracy(Xte, yte)),
                     "victim_accuracy_on_transferred_fgsm": r3(base.accuracy(transfer, yte))})
    return {"victim_clean_accuracy": r3(base.accuracy(Xte, yte)), "runs": rows}


def membership(Xtr, ytr, Xte, yte):
    Xin, yin, Xout, yout = Xtr[:N_MEMBERS], ytr[:N_MEMBERS], Xte[:N_MEMBERS], yte[:N_MEMBERS]
    rows = []
    for training, kw in (("overfit (300 epochs, no L2)", {}), ("regularized (L2 0.02)", {"l2": 0.02})):
        m = MLP().fit(Xin, yin, epochs=300, **kw)
        for mode in ("probs", "label"):
            rows.append({"training": training, "api_output": mode,
                         "test_accuracy": r3(m.accuracy(Xte, yte)),
                         "attack_advantage": r3(A.membership_advantage(
                             A.PredictionAPI(m, mode), Xin, yin, Xout, yout))})
    return {"members": N_MEMBERS, "non_members": N_MEMBERS, "runs": rows}


def supply_chain(base, Xte, yte):
    os.environ.pop("DIGITNET_PWNED", None)
    out = {}
    with tempfile.TemporaryDirectory() as d:
        good, evil = os.path.join(d, "model.npz"), os.path.join(d, "model.pkl")
        base.save(good)
        pinned = D.file_sha256(good)                   # recorded when the model was trained
        A.write_malicious_model(evil, base)

        m = D.unsafe_load(evil)
        out["pickle_load_of_malicious_file"] = {
            "payload_ran": "DIGITNET_PWNED" in os.environ,
            "model_still_works": r3(m.accuracy(Xte, yte))}
        os.environ.pop("DIGITNET_PWNED", None)

        try:
            D.safe_load(evil, pinned)
            refused = None
        except D.UntrustedModel as e:
            refused = str(e)
        out["safe_load_of_malicious_file"] = {"payload_ran": "DIGITNET_PWNED" in os.environ,
                                              "refused": refused}

        out["safe_load_of_genuine_file"] = {"accuracy": r3(D.safe_load(good, pinned).accuracy(Xte, yte))}

        with np.load(good) as a:                       # tampered weights, plain format
            w = {k: a[k] for k in a.files}
        w["b2"] = w["b2"] + np.eye(10)[A.TARGET] * 50
        np.savez(good, **w)
        try:
            D.safe_load(good, pinned)
            refused = None
        except D.UntrustedModel as e:
            refused = str(e)
        out["safe_load_of_tampered_weights"] = {"refused": refused}
    return out


def to_md(rep):
    ev, po, ex, me, sc = (rep[k] for k in ("evasion", "poisoning", "extraction", "membership", "supply_chain"))
    u, h = ev["undefended"], ev["adversarially_trained"]
    L = ["# Neural-network attack and defense evaluation", "",
         "Model: 64-64-10 MLP on 8x8 handwritten digits (900 train / 450 test / 447 attacker pool).", "",
         f"- Fingerprint: `{rep['fingerprint']}`", "",
         "## 1. Evasion: adversarial examples (ATLAS AML.T0015, AML.T0043)", "",
         "Test accuracy when every pixel may change by at most ε (0..1 scale; 0.10 ≈ 1.6 of 16 gray levels).", "",
         "| Model | Clean | " + " | ".join(f"FGSM ε={e}" for e in EPS) + " | " + " | ".join(f"PGD ε={e}" for e in EPS) + " |",
         "|---|---|" + "---|" * (2 * len(EPS))]
    for name, m in (("Undefended", u), ("Adversarially trained (ε=0.15)", h)):
        L.append(f"| {name} | {m['clean_accuracy']:.1%} | " +
                 " | ".join(f"{m['fgsm'][str(e)]:.1%}" for e in EPS) + " | " +
                 " | ".join(f"{m['pgd'][str(e)]:.1%}" for e in EPS) + " |")
    L += ["", "## 2. Poisoning: backdoor trigger (ATLAS AML.T0020, AML.T0018)", "",
          f"{po['poison_rows']} of {po['of_training_rows']} training images carry a 3-pixel corner "
          f"trigger and the label {po['target_label']}. Backdoor success = share of non-{po['target_label']} "
          f"test digits read as {po['target_label']} once the trigger is added.", "",
          "| Model | Clean accuracy | Backdoor success |", "|---|---|---|"]
    for name, k in (("Trained on clean data", "clean_data_model"), ("Trained on poisoned data", "poisoned_model"),
                    ("Retrained after activation clustering", "after_activation_clustering")):
        L.append(f"| {name} | {po[k]['clean_accuracy']:.1%} | {po[k]['backdoor_success']:.1%} |")
    L += ["", f"Activation clustering removed **{po['removed_poison_rows']} of {po['poison_rows']}** poisoned rows "
          f"and **{po['removed_clean_rows']}** clean rows.", "",
          "| Label | Smaller cluster | Model trained without it reads it as another digit (mean confidence) | Removed |", "|---|---|---|---|"]
    L += [f"| {f['label']} | {f['cluster_size']} | {f['relabel_confidence']:.0%} | {'**yes**' if f['removed'] else 'no'} |"
          for f in po["cluster_findings"]]
    L += ["", "Operating range: the same defense at other poison rates.", "",
          "| Poisoned rows | Poison removed | Clean removed | Backdoor success after |", "|---|---|---|---|"]
    L += [f"| {o['poison_rows']} | {o['removed_poison_rows']} | {o['removed_clean_rows']} | {o['backdoor_success_after']:.1%} |"
          for o in po["operating_range"]]
    L += ["", "## 3. Extraction: cloning through the API (ATLAS AML.T0024.002)", "",
          f"Victim clean accuracy {ex['victim_clean_accuracy']:.1%}. Transferred FGSM: ε=0.10 examples crafted "
          "on the clone only, then sent to the victim.", "",
          "| API returns | Query budget | Queries answered | Clone agrees with victim | Victim accuracy on transferred attack |",
          "|---|---|---|---|---|"]
    L += [f"| {r['api_output']} | {r['query_budget'] or 'none'} | {r['queries_answered']} | "
          f"{r['clone_agreement']:.1%} | {r['victim_accuracy_on_transferred_fgsm']:.1%} |" for r in ex["runs"]]
    L += ["", "## 4. Membership inference (ATLAS AML.T0024.000)", "",
          f"Model trained on {me['members']} images. Advantage = best (true-positive rate − false-positive rate) "
          "at telling those images from unseen ones; 0 is a coin flip.", "",
          "| Training | API returns | Test accuracy | Attack advantage |", "|---|---|---|---|"]
    L += [f"| {r['training']} | {r['api_output']} | {r['test_accuracy']:.1%} | {r['attack_advantage']:.2f} |"
          for r in me["runs"]]
    L += ["", "## 5. Supply chain: malicious model file (ATLAS AML.T0010.003, AML.T0011)", "",
          "| Load | Attacker code ran | Result |", "|---|---|---|",
          f"| `pickle.load` of the malicious file | **{'YES' if sc['pickle_load_of_malicious_file']['payload_ran'] else 'no'}** | "
          f"model still works ({sc['pickle_load_of_malicious_file']['model_still_works']:.1%}), so nobody notices |",
          f"| `safe_load` of the malicious file | {'YES' if sc['safe_load_of_malicious_file']['payload_ran'] else 'no'} | "
          f"refused: {sc['safe_load_of_malicious_file']['refused']} |",
          f"| `safe_load` of the genuine file | no | loads, accuracy {sc['safe_load_of_genuine_file']['accuracy']:.1%} |",
          f"| `safe_load` of tampered weights (.npz) | no | refused: {sc['safe_load_of_tampered_weights']['refused']} |"]
    return "\n".join(L) + "\n"


def main():
    (Xtr, ytr), (Xte, yte), pool = splits()
    rep = {}
    rep["evasion"], base = evasion(Xtr, ytr, Xte, yte)
    rep["poisoning"] = poisoning(Xtr, ytr, Xte, yte, base)
    rep["extraction"] = extraction(base, pool, Xte, yte)
    rep["membership"] = membership(Xtr, ytr, Xte, yte)
    rep["supply_chain"] = supply_chain(base, Xte, yte)
    rep["fingerprint"] = hashlib.sha256(json.dumps(rep, sort_keys=True).encode()).hexdigest()[:16]
    os.makedirs(os.path.join(HERE, "reports"), exist_ok=True)
    with open(os.path.join(HERE, "reports", "nn_eval.json"), "w") as f:
        json.dump(rep, f, indent=2)
    with open(os.path.join(HERE, "reports", "nn_eval.md"), "w") as f:
        f.write(to_md(rep))
    print(to_md(rep))
    print("report written to reports/nn_eval.md")


if __name__ == "__main__":
    main()
