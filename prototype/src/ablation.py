"""Phase 10 — ablation harness.

Classifies each (component, version, CVE) pair as AFFECTED / NOT_AFFECTED under
three conditions and scores each against ground truth:

  - system     : deterministic version-aware rule (the KG's logic; reference).
  - ungrounded : the LLM given only name+version+CVE (training memory).
  - grounded   : the LLM given the deciding fact (fixed version) + the comparison rule.

Positive class = AFFECTED. Metrics: precision, recall, false-positive rate, F1, accuracy.
Only the LLM conditions require Ollama.
"""
import json
from pathlib import Path
from packaging.version import Version


def _norm(v):
    return v.replace("p", ".").replace("_", ".")


def version_lt(a, b):
    try:
        return Version(_norm(a)) < Version(_norm(b))
    except Exception:
        return str(a) < str(b)


def load_gt(path):
    return json.loads(Path(path).read_text())


# ---------------- prompts ----------------
def ungrounded_prompt(e):
    return (f'Is the software package "{e["name"]}" version "{e["version"]}" affected '
            f'by {e["cve"]}?\n'
            'End your reply with a final line exactly in this form:\n'
            'VERDICT: AFFECTED   or   VERDICT: NOT_AFFECTED')


def grounded_prompt(e):
    return (f'Determine whether an installed software version is affected by a vulnerability.\n'
            f'- {e["cve"]} affecting {e["name"]} is fixed in version {e["fixed_version"]}.\n'
            f'- The installed version is {e["version"]}.\n'
            'Rule: the installed version is AFFECTED if it is lower than the fixed version, '
            'and NOT_AFFECTED if it is greater than or equal to the fixed version.\n'
            'End your reply with a final line exactly in this form:\n'
            'VERDICT: AFFECTED   or   VERDICT: NOT_AFFECTED')


# ---------------- parsing ----------------
def parse_verdict(ans):
    """Return True if the answer means AFFECTED, else False. Robust to verbose replies."""
    a = (ans or "").upper()
    seg = a.split("VERDICT")[-1] if "VERDICT" in a else a
    if "NOT_AFFECTED" in seg or "NOT AFFECTED" in seg or "UNAFFECTED" in seg or "NOT VULNERABLE" in seg:
        return False
    if "AFFECTED" in seg or "VULNERABLE" in seg:
        return True
    # whole-text fallback
    if "NOT AFFECTED" in a or "NOT_AFFECTED" in a or "UNAFFECTED" in a:
        return False
    return ("AFFECTED" in a) or ("VULNERABLE" in a)


# ---------------- classifiers (True = predicted AFFECTED) ----------------
def classify_system(e, **kw):
    return version_lt(e["version"], e["fixed_version"])


def classify_ungrounded(e, model="llama3.1:8b"):
    import llm
    return parse_verdict(llm.ask(ungrounded_prompt(e), model=model))


def classify_grounded(e, model="llama3.1:8b"):
    import llm
    return parse_verdict(llm.ask(grounded_prompt(e), model=model))


# ---------------- metrics ----------------
def metrics(preds, truth):
    TP = sum(1 for p, t in zip(preds, truth) if p and t)
    FP = sum(1 for p, t in zip(preds, truth) if p and not t)
    FN = sum(1 for p, t in zip(preds, truth) if not p and t)
    TN = sum(1 for p, t in zip(preds, truth) if not p and not t)
    prec = TP / (TP + FP) if TP + FP else 0.0
    rec  = TP / (TP + FN) if TP + FN else 0.0
    fpr  = FP / (FP + TN) if FP + TN else 0.0
    f1   = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    acc  = (TP + TN) / len(truth) if truth else 0.0
    return dict(TP=TP, FP=FP, FN=FN, TN=TN,
                precision=round(prec, 3), recall=round(rec, 3),
                FPR=round(fpr, 3), F1=round(f1, 3), accuracy=round(acc, 3))


def run(gt, classifier, model="llama3.1:8b"):
    truth = [e["affected"] for e in gt]
    preds = [classifier(e, model=model) for e in gt]
    return preds, metrics(preds, truth)


def debug(gt, model="llama3.1:8b"):
    """Return per-pair raw LLM answers + parsed decision, to see what the model said."""
    import llm
    rows = []
    for e in gt:
        ru = llm.ask(ungrounded_prompt(e), model=model)
        rg = llm.ask(grounded_prompt(e), model=model)
        rows.append(dict(name=e["name"], version=e["version"], cve=e["cve"],
                         truth=e["affected"],
                         ung=parse_verdict(ru), ung_raw=" ".join(ru.split())[:100],
                         gnd=parse_verdict(rg), gnd_raw=" ".join(rg.split())[:100]))
    return rows
