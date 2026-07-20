"""Phase 6 — Cybersecurity intelligence adapter (version-aware correlation).

Reads a local CVE snapshot and the build facts, and produces:
  - Vulnerability + Weakness nodes (CVE -> CWE)
  - a ComponentVulnerabilityMatch per (component, CVE) with a VEX status decided by
    comparing the component's version to the CVE's fixed_version
  - a RiskAssessment + Evidence for AFFECTED matches only

The version comparison is what suppresses false positives: a component whose version
is >= the fixed version is marked NotAffected even though its name matches.
"""
import json, re
from datetime import datetime, timezone
from pathlib import Path
from rdflib import Graph, Namespace, Literal, RDF, XSD
from rdflib.namespace import RDFS, PROV
from packaging.version import Version

SSC  = Namespace("http://systemscyber.colostate.edu/ssc#")
DATA = Namespace("http://systemscyber.colostate.edu/ssc/data#")

SEV  = {"Critical": SSC.Critical, "High": SSC.High, "Medium": SSC.Medium, "Low": SSC.Low}
RISK = {"Critical": SSC.RiskCritical, "High": SSC.RiskHigh, "Medium": SSC.RiskMedium, "Low": SSC.RiskLow}


def _norm(v):
    # normalize e.g. openssh "9.6p1" -> "9.6.1" so it parses as a version
    return v.replace("p", ".").replace("_", ".")


def version_lt(a, b):
    """True if version a < version b (i.e., a is affected, below the fixed version)."""
    try:
        return Version(_norm(a)) < Version(_norm(b))
    except Exception:
        return str(a) < str(b)


def _components(build_ttl):
    g = Graph(); g.parse(build_ttl, format="turtle")
    q = (f"PREFIX ssc: <{SSC}> "
         "SELECT ?c ?purl ?ver WHERE { ?c ssc:identifiedByPurl ?purl ; ssc:hasVersion ?ver }")
    out = []
    for c, purl, ver in g.query(q):
        m = re.search(r"/([^/@]+)@", str(purl))
        out.append((c, m.group(1) if m else None, str(ver)))
    return out


def correlate(build_ttl, snapshot_json, out_ttl):
    comps = _components(build_ttl)
    snap  = json.loads(Path(snapshot_json).read_text())
    g = Graph(); g.bind("ssc", SSC); g.bind("", DATA); g.bind("prov", PROV)
    ts  = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    src = DATA["nvd_snapshot"]
    stats = {"affected": 0, "not_affected": 0}

    for e in snap:
        cve, cwe = DATA[e["cve"]], DATA[e["cwe"]]
        g.add((cve, RDF.type, SSC.Vulnerability))
        g.add((cve, RDFS.label, Literal(e["cve"])))
        g.add((cve, SSC.hasWeakness, cwe))
        g.add((cve, SSC.hasSeverity, SEV.get(e["severity"], SSC.Medium)))
        g.add((cve, SSC.hasCvssScore, Literal(e["cvss"], datatype=XSD.decimal)))
        g.add((cwe, RDF.type, SSC.Weakness))
        g.add((cwe, RDFS.label, Literal(e.get("cwe_label", e["cwe"]))))

        for c, name, ver in comps:
            if name != e["package"]:
                continue
            affected = version_lt(ver, e["fixed_version"])
            mid = DATA[f"match_{e['package']}_{e['cve']}"]
            vid = DATA[f"vex_{e['package']}_{e['cve']}"]
            g.add((mid, RDF.type, SSC.ComponentVulnerabilityMatch))
            g.add((mid, SSC.matchesComponent, c))
            g.add((mid, SSC.matchesVulnerability, cve))
            g.add((mid, SSC.matchMethod, SSC.NormalizedNameVersion))
            g.add((mid, SSC.hasConfidence, Literal(1.0, datatype=XSD.decimal)))
            g.add((mid, SSC.hasVEXStatus, vid))
            g.add((vid, RDF.type, SSC.VEXStatement))
            g.add((vid, SSC.vexStatus, SSC.Affected if affected else SSC.NotAffected))
            if affected:
                stats["affected"] += 1
                rid, ev = DATA[f"risk_{e['package']}_{e['cve']}"], DATA[f"ev_{e['cve']}"]
                g.add((rid, RDF.type, SSC.RiskAssessment))
                g.add((rid, SSC.assesses, mid))
                g.add((rid, SSC.hasRiskLevel, RISK.get(e["severity"], SSC.RiskMedium)))
                g.add((rid, SSC.supportedBy, ev))
                g.add((ev, RDF.type, SSC.Evidence))
                g.add((ev, SSC.hasTimestamp, Literal(ts, datatype=XSD.dateTime)))
                g.add((ev, PROV.wasAttributedTo, src))
            else:
                stats["not_affected"] += 1

    g.serialize(destination=str(out_ttl), format="turtle")
    return out_ttl, len(g), stats


if __name__ == "__main__":
    out, n, stats = correlate("../data/uthp_build.ttl", "../data/intel_snapshot.json",
                              "../data/uthp_intel.ttl")
    print(f"Wrote {n} triples to {out}; matches: {stats}")
