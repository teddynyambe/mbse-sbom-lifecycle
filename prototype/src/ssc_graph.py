"""Tiny reusable helper for the SSC knowledge graph.

Loads ontology + data, runs OWL-RL inference, and executes SPARQL.
No graph database — everything is in-memory RDF (rdflib).
"""
from pathlib import Path
from rdflib import Graph
import owlrl

SSC  = "http://systemscyber.colostate.edu/ssc#"
DATA = "http://systemscyber.colostate.edu/ssc/data#"
PREFIXES = f"PREFIX ssc: <{SSC}>\nPREFIX : <{DATA}>\n"

# Default ontology location relative to prototype/notebooks/ or prototype/src/
ONTO_DEFAULT = Path(__file__).resolve().parents[1] / "ontology-ssc" / "ssc.ttl"


def load(data_files, onto=ONTO_DEFAULT, reason=True):
    """Load the ontology plus one or more data files; optionally materialize inference."""
    g = Graph()
    g.parse(str(onto), format="turtle")
    if isinstance(data_files, (str, Path)):
        data_files = [data_files]
    for f in data_files:
        g.parse(str(f), format="turtle")
    if reason:
        owlrl.DeductiveClosure(owlrl.OWLRL_Semantics).expand(g)
    return g


def q(g, sparql):
    """Run a SPARQL string (prefixes ssc: and : are added automatically)."""
    return list(g.query(PREFIXES + sparql))


def run_file(g, path):
    """Run a saved .rq query file (query body only, no prefixes needed)."""
    return q(g, Path(path).read_text())


def short(x):
    """Trim a URI to its readable local name."""
    return str(x).split("#")[-1].split("/")[-1]
