"""Phase 9 — GraphRAG retrieval.

Given a component, pull the relevant subgraph (version, vulnerability match, CWE,
severity, VEX status, risk, and the network impact path) and format it as a
compact, provenance-bearing context block for the LLM. Retrieval only — no reasoning.
"""
SSC  = "http://systemscyber.colostate.edu/ssc#"
DATA = "http://systemscyber.colostate.edu/ssc/data#"
RDFS = "http://www.w3.org/2000/01/rdf-schema#"
PRE  = f"PREFIX ssc: <{SSC}>\nPREFIX rdfs: <{RDFS}>\nPREFIX : <{DATA}>\n"


def _s(x):
    return str(x).split("#")[-1].split("/")[-1] if x is not None else None


def component_iri(g, name_substr):
    """Find a component IRI whose local name contains a substring (e.g. 'openssh')."""
    for (c,) in g.query(PRE + "SELECT ?c WHERE { ?c a ssc:SoftwareComponent }"):
        if name_substr.lower() in str(c).lower():
            return str(c)
    return None


def retrieve(g, comp):
    comp = str(comp)
    q = PRE + f"""SELECT ?ver ?cve ?cweLbl ?sev ?cvss ?risk ?vex ?dev ?net ?ecu ?fn WHERE {{
        <{comp}> ssc:hasVersion ?ver .
        OPTIONAL {{
          ?m ssc:matchesComponent <{comp}> ; ssc:matchesVulnerability ?cve ;
             ssc:hasVEXStatus/ssc:vexStatus ?vex .
          OPTIONAL {{ ?cve ssc:hasWeakness ?cwe . OPTIONAL {{ ?cwe rdfs:label ?cweLbl }} }}
          OPTIONAL {{ ?cve ssc:hasSeverity ?sev }}
          OPTIONAL {{ ?cve ssc:hasCvssScore ?cvss }}
          OPTIONAL {{ ?ra ssc:assesses ?m ; ssc:hasRiskLevel ?risk }}
        }}
        OPTIONAL {{ <{comp}> ssc:runsOn ?dev . ?dev ssc:connectsTo ?net .
                   ?net ssc:reaches ?ecu . ?ecu ssc:supports ?fn }}
    }}"""
    rows = list(g.query(q))
    if not rows:
        return None
    ver = _s(rows[0].ver)
    vulns, impact = {}, set()
    for r in rows:
        if r.cve:
            vulns[_s(r.cve)] = dict(cwe=_s(r.cweLbl) or "-", sev=_s(r.sev),
                                    cvss=str(r.cvss) if r.cvss else None,
                                    risk=_s(r.risk), vex=_s(r.vex))
        if r.fn:
            impact.add((_s(r.dev), _s(r.net), _s(r.ecu), _s(r.fn)))
    return dict(name=_s(comp), version=ver, vulns=vulns, impact=impact)


def context_text(g, comp):
    """Human/LLM-readable fact block retrieved from the graph."""
    f = retrieve(g, comp)
    if not f:
        return "(no facts found)"
    lines = [f"Component: {f['name']} version {f['version']}."]
    for cve, d in f["vulns"].items():
        lines.append(
            f"Vulnerability match: {cve} — weakness {d['cwe']} — severity {d['sev']} "
            f"(CVSS {d['cvss']}) — VEX status: {d['vex']} — risk {d['risk']}.")
    for dev, net, ecu, fn in f["impact"]:
        lines.append(
            f"Impact path: {f['name']} runs on {dev}, which connects to {net}, "
            f"which reaches {ecu}, which supports {fn} (a safety function).")
    lines.append("Source of intelligence: local NVD snapshot.")
    return "\n".join(lines)
