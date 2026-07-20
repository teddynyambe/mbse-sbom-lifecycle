# prototype

Instantiation of the SBOM Lifecycle Governance reference architecture around Yocto/UTHP.
Orchestration is done in Jupyter notebooks; semantic backend is file-based (no graph database).

## Layout
```
prototype/
├── requirements.txt
├── notebooks/        # orchestration (start here: 00_smoke_test.ipynb)
├── src/              # adapters & services (added in later phases)
├── data/             # generated RDF fact files (per build / intelligence)
├── ontology-ssc/     # OWL ontology (ssc.ttl) + SHACL shapes
└── uthp-yocto/       # UTHP content
    ├── meta-uthp/    # Yocto layer (recipes -> component/version facts)
    └── (docs)        # README, Instruction_Manual, Yocto/, Debian/
```
The ontology lives in `ontology-ssc/ssc.ttl` (with SHACL shapes in `ontology-ssc/shapes/`).

## Set up (run locally on your machine)
A virtual environment must be created on **your** machine (not portable across OS).
```bash
cd prototype
python3 -m venv .venv
source .venv/bin/activate            # macOS/Linux
pip install -r requirements.txt
python -m ipykernel install --user --name ssc-proto   # notebook kernel
jupyter lab                          # open notebooks/00_smoke_test.ipynb
```

## Local model (Ollama)
```bash
ollama pull llama3.1:8b              # primary model for the ablation
```
Keep one model fixed, temperature 0, and record the exact tag/digest for reproducibility.

## Phases (see ../PROGRESS_CHECKLIST.md)
1. Ontology (done) → `ontology-ssc/ssc.ttl`
2. Seed dataset → `data/seed.ttl`
3. SHACL shapes → `../ontology-ssc/shapes/`
4. Reasoning + SPARQL (in notebooks)
5–9. Adapters, correlation, risk, GraphRAG + LLM
10. Verification + ablation
