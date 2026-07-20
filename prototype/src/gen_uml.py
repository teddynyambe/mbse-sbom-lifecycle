"""Generate a high-level UML class diagram of the SSC ontology via Graphviz.

Classes only (no attribute/individual compartments). Generalizations use the UML
hollow triangle; object properties are shown as labelled directed associations;
reasoner-derived properties (runsOn, mayImpactFunction) are dashed. Colours match
the instance-graph figure (fig_kg_graph) for a cohesive paper.
"""
import subprocess

# name -> (fill, fontcolor, stereotype or None)
N = {
    # ---- supply-chain / deployment structure ----
    "Build":            ("#d7dbe0", "#111111", None),
    "Artifact":         ("#a9c7e6", "#111111", None),
    "FirmwareImage":    ("#79b0e0", "#111111", None),
    "SoftwareComponent":("#4a86c5", "#ffffff", None),
    "Supplier":         ("#d7dbe0", "#111111", None),
    "TargetDevice":     ("#3fae9f", "#ffffff", None),
    "Gateway":          ("#8fd0c6", "#111111", None),
    "TelematicsUnit":   ("#8fd0c6", "#111111", None),
    "InfotainmentUnit": ("#8fd0c6", "#111111", None),
    "DomainController": ("#8fd0c6", "#111111", None),
    "ECU":              ("#b5651d", "#ffffff", None),
    "VehicleNetwork":   ("#2f8f7f", "#ffffff", None),
    "VehicleFunction":  ("#d98c8c", "#111111", None),
    "SafetyFunction":   ("#b22222", "#ffffff", None),
    # ---- vulnerability intelligence & governance ----
    "Vulnerability":            ("#d9534f", "#ffffff", None),
    "Weakness":                 ("#8e6bc0", "#ffffff", None),
    "ComponentVulnerabilityMatch": ("#3aa76d", "#ffffff", None),
    "VEXStatement":             ("#e0a83a", "#111111", None),
    "RiskAssessment":           ("#cf7b3a", "#ffffff", None),
    "Remediation":              ("#6fa05a", "#ffffff", None),
    "Attestation":              ("#c9bfe0", "#111111", None),
    "Evidence":                 ("#b8b8b8", "#111111", None),
    # ---- controlled vocabularies (enumerations) ----
    "Severity":   ("#eceff1", "#111111", "enumeration"),
    "VEXStatus":  ("#eceff1", "#111111", "enumeration"),
    "RiskLevel":  ("#eceff1", "#111111", "enumeration"),
    "MatchMethod":("#eceff1", "#111111", "enumeration"),
}

GEN = [  # (child, parent)  -> UML generalization (hollow triangle)
    ("FirmwareImage", "Artifact"),
    ("Gateway", "TargetDevice"), ("TelematicsUnit", "TargetDevice"),
    ("InfotainmentUnit", "TargetDevice"), ("DomainController", "TargetDevice"),
    ("SafetyFunction", "VehicleFunction"),
]

ASSOC = [  # (src, dst, label, derived?)
    ("SoftwareComponent", "FirmwareImage", "includedIn", False),
    ("SoftwareComponent", "SoftwareComponent", "dependsOn", False),
    ("SoftwareComponent", "Supplier", "suppliedBy", False),
    ("Artifact", "Build", "producedBy", False),
    ("FirmwareImage", "TargetDevice", "deployedOn", False),
    ("TargetDevice", "VehicleNetwork", "connectsTo", False),
    ("VehicleNetwork", "ECU", "reaches", False),
    ("ECU", "VehicleFunction", "supports", False),
    ("SoftwareComponent", "TargetDevice", "runsOn", True),
    ("SoftwareComponent", "VehicleFunction", "mayImpactFunction", True),
    ("Vulnerability", "Weakness", "hasWeakness", False),
    ("Vulnerability", "Severity", "hasSeverity", False),
    ("Vulnerability", "Remediation", "remediatedBy", False),
    ("ComponentVulnerabilityMatch", "SoftwareComponent", "matchesComponent", False),
    ("ComponentVulnerabilityMatch", "Vulnerability", "matchesVulnerability", False),
    ("ComponentVulnerabilityMatch", "VEXStatement", "hasVEXStatus", False),
    ("ComponentVulnerabilityMatch", "MatchMethod", "matchMethod", False),
    ("VEXStatement", "VEXStatus", "vexStatus", False),
    ("RiskAssessment", "ComponentVulnerabilityMatch", "assesses", False),
    ("RiskAssessment", "RiskLevel", "hasRiskLevel", False),
    ("RiskAssessment", "Evidence", "supportedBy", False),
    ("Remediation", "Attestation", "attestedBy", False),
]


def node(name):
    fill, fc, ster = N[name]
    if ster:
        lbl = (f'<<FONT POINT-SIZE="9"><I>&#171;{ster}&#187;</I></FONT>'
               f'<BR/><B>{name}</B>>')
    else:
        lbl = f'<<B>{name}</B>>'
    return (f'  "{name}" [label={lbl}, fillcolor="{fill}", fontcolor="{fc}"];')


def build_dot():
    L = ['digraph SSC {',
         '  rankdir=TB; splines=true; overlap=false;',
         '  nodesep=0.35; ranksep=0.75; pad=0.3;',
         '  node [shape=box, style="filled", fontname="Helvetica",'
         ' fontsize=11, margin="0.14,0.07", penwidth=1.1, color="#333333"];',
         '  edge [fontname="Helvetica", fontsize=9, color="#5a5a5a",'
         ' fontcolor="#3a3a3a", arrowsize=0.8];', '']
    for n in N:
        L.append(node(n))
    L.append('')
    L.append('  // ---- generalizations (UML hollow triangle) ----')
    L.append('  edge [arrowhead=empty, color="#333333", style=solid];')
    for c, p in GEN:
        L.append(f'  "{c}" -> "{p}";')
    L.append('')
    L.append('  // ---- associations (object properties) ----')
    for s, d, lab, der in ASSOC:
        if der:
            L.append(f'  "{s}" -> "{d}" [label="{lab}", arrowhead=vee,'
                     f' style=dashed, color="#b22222", fontcolor="#b22222"];')
        else:
            L.append(f'  "{s}" -> "{d}" [label="{lab}", arrowhead=vee,'
                     f' style=solid, color="#5a5a5a"];')
    # ---- legend (unconnected node, pinned to the bottom) ----
    L.append('')
    L.append('  legend [shape=none, margin=0, fillcolor="#ffffff",'
             ' style=filled, label=<')
    L.append('    <TABLE BORDER="1" CELLBORDER="0" CELLSPACING="3"'
             ' CELLPADDING="3" COLOR="#999999">')
    L.append('    <TR><TD ALIGN="LEFT"><B>Legend</B></TD></TR>')
    L.append('    <TR><TD ALIGN="LEFT">&#9651;&#8212; generalization'
             ' (subclass of)</TD></TR>')
    L.append('    <TR><TD ALIGN="LEFT">&#8212;&#8250; object property'
             ' (asserted)</TD></TR>')
    L.append('    <TR><TD ALIGN="LEFT"><FONT COLOR="#b22222">- - &#8250;'
             ' reasoner-derived property</FONT></TD></TR>')
    if any(v[2] for v in N.values()):     # only if enumerations are shown
        L.append('    <TR><TD ALIGN="LEFT"><I>&#171;enumeration&#187;</I>'
                 ' controlled vocabulary</TD></TR>')
    L.append('    </TABLE>>];')
    anchor = "Build" if "Build" in N else next(iter(N))
    L.append(f'  "{anchor}" -> legend [style=invis];')
    L.append('}')
    return "\n".join(L)


# Minimal core: the classes needed to tell the paper's story (deployment/safety
# backbone + vulnerability correlation). Enumerations, provenance, remediation
# and the extra device subtypes are omitted.
CORE = {"SoftwareComponent", "FirmwareImage", "TargetDevice", "VehicleNetwork",
        "ECU", "VehicleFunction", "SafetyFunction", "Vulnerability", "Weakness",
        "ComponentVulnerabilityMatch", "VEXStatement"}


def render(path, minimal=False):
    global N, GEN, ASSOC
    fullN, fullG, fullA = N, GEN, ASSOC
    if minimal:
        N = {k: v for k, v in N.items() if k in CORE}
        GEN = [(c, p) for c, p in GEN if c in CORE and p in CORE]
        ASSOC = [a for a in ASSOC if a[0] in CORE and a[1] in CORE]
    dot = build_dot()
    N, GEN, ASSOC = fullN, fullG, fullA
    with open(path + ".dot", "w") as f:
        f.write(dot)
    for fmt in ("png", "svg"):
        args = ["dot", f"-T{fmt}", path + ".dot", "-o", path + "." + fmt]
        if fmt == "png":
            args.insert(2, "-Gdpi=200")
        subprocess.run(args, check=True)
    print("wrote", path + ".png /.svg")


if __name__ == "__main__":
    render("../../fig_ontology_uml")
    render("../../fig_ontology_uml_minimal", minimal=True)
