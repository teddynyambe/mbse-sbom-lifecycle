"""Phase 9 — LLM explanation via a local Ollama model.

Two modes for the ablation:
  - grounded:   the LLM is given the retrieved graph facts (GraphRAG).
  - ungrounded: the LLM is given only the component name/version and CVE id.
Same model, same task; grounding is the only variable.
"""
import ollama

MODEL = "llama3.1:8b"

SYSTEM = ("You are a cybersecurity analyst for safety-critical vehicle software. "
          "Be precise and do not invent facts.")

GROUNDED_TMPL = """Using ONLY the facts below, answer:
1. Is the component affected by the vulnerability? (If the VEX status is NotAffected, say it is NOT affected and why.)
2. If affected, what is the potential impact on the vehicle, following the impact path?
3. Cite the evidence source.
Do not use outside knowledge beyond these facts.

FACTS:
{facts}
"""

UNGROUNDED_TMPL = """A scanner reports that the software package "{name}" version "{version}" is present in a device, and that {cve} exists.
1. Is this package affected by {cve}?
2. What could the impact be for a vehicle?
Answer concisely."""


def ask(prompt, model=MODEL, temperature=0.0):
    r = ollama.chat(
        model=model,
        messages=[{"role": "system", "content": SYSTEM},
                  {"role": "user", "content": prompt}],
        options={"temperature": temperature},
    )
    return r["message"]["content"].strip()


def explain_grounded(g, comp, **kw):
    from graphrag import context_text
    return ask(GROUNDED_TMPL.format(facts=context_text(g, comp)), **kw)


def explain_ungrounded(name, version, cve, **kw):
    return ask(UNGROUNDED_TMPL.format(name=name, version=version, cve=cve), **kw)
