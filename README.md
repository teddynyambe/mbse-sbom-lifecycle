# MBSE SBOM Lifecycle Governance — Prototype

An **ontology-grounded** prototype for software supply-chain security: it turns
heterogeneous build metadata and cybersecurity intelligence into *validated,
reasoned, evidence-backed* vulnerability impact assessments — and shows that
grounding a language model in that knowledge graph corrects errors the model
makes on its own.

Design thesis: **formal model at the center, LLM at the edge.** The OWL reasoner
derives facts, SHACL validates structure, GraphRAG retrieves context — three
distinct roles. The LLM is the *explanation interface*, not the reasoner.

This repository contains the runnable prototype accompanying a research paper on
representing SBOM lifecycle data with MBSE. The worked scenario instantiates the
reference architecture around the [UTHP](https://github.com/SystemsCyber/UTHP)
Yocto build.

## Headline result

A grounded-vs-ungrounded ablation over a curated ground-truth set (3 real
vulnerabilities + 4 patched decoys):

| Condition  | Accuracy | Recall | Notes |
|------------|---------:|-------:|-------|
| Ungrounded (LLM alone) | 0.57 | 0.00 | model abstains → misses every real vuln |
| **Grounded (GraphRAG + KG)** | **1.00** | **1.00** | deciding facts retrieved from the graph |

The reasoner pivots a vulnerable component through `deployedOn → connectsTo →
reaches → supports` to the vehicle **safety function** it may impact — an
inference a flat CVE scanner or an ungrounded LLM cannot reproduce.

## How it works

```
Yocto build metadata        Cybersecurity intelligence
        │                            │
   Build adapter               Intelligence adapter
        └───────────┬────────────────┘
                    ▼   normalize → RDF facts (+ PROV-O provenance)
        RDF knowledge graph  (Turtle files, in-memory rdflib — no graph DB)
          ┌─────────┴─────────┐
          ▼                   ▼
     SHACL validate      OWL-RL reason  → inferred facts
                              ▼
                   risk / impact analysis
                              ▼
                     SPARQL  →  GraphRAG retrieval  →  edge LLM (Ollama)
                              ▼
             explanation + impact assessment + evidence path
```

Modeling conventions worth knowing before reading the graph: schema terms use the
`ssc:` namespace and instances use `:` (`…/ssc/data#`); a component↔vulnerability
link is **always** reified through a `ComponentVulnerabilityMatch` (recording
match method, confidence, and VEX status) — there is no direct `affectedBy` edge.
See [`prototype/ontology-ssc/README.md`](prototype/ontology-ssc/README.md) for
the full ontology and a "which property do I use?" guide.

## Layout

```
prototype/
├── notebooks/      # orchestration — run 00 → 07 in order (start at 00_smoke_test)
├── src/            # adapters & services (build, intelligence, GraphRAG, LLM, ablation)
├── ontology-ssc/   # OWL ontology (ssc.ttl) + SHACL shapes
├── queries/        # SPARQL competency questions (CQ1, CQ2, CQ7, CQ10, CQ12)
├── data/           # seed + generated RDF fact files
└── eval/           # ground_truth.json for the ablation
```

Each notebook corresponds to one phase; the notebooks are the entry point and the
`src/` modules are imported by them.

## Setup

```bash
cd prototype
python3 -m venv .venv
source .venv/bin/activate            # macOS/Linux
pip install -r requirements.txt
python -m ipykernel install --user --name ssc-proto
jupyter lab                          # open notebooks/00_smoke_test.ipynb
```

Phases 1–5 (ontology, reasoning, SHACL, build adapter) run without a model.
Phases 9–10 (LLM explanation + ablation) need a local model via **Ollama**:

```bash
ollama pull llama3.1:8b              # fixed model; temperature 0, seed 42
```

For reproducibility keep the model tag fixed at temperature 0 and record the exact
tag/digest.

## Semantic-web stack

`rdflib` · `owlrl` (OWL 2 RL inference) · `pyshacl` · `ollama` — everything is
file-based and in-memory; no graph database required.

## Acknowledgements

The Yocto layer and build content derive from
[SystemsCyber/UTHP](https://github.com/SystemsCyber/UTHP) (not vendored here —
clone it separately if you need the meta-uthp recipes).
