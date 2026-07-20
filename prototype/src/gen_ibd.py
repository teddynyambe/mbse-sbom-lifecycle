"""Generate the SysML-style Internal Block Diagram (IBD) of the System of Interest.

Shows the six logical parts of the SBOM Lifecycle Governance System, the
delegation of the external ports (p1-p6 from the enclosing Software Supply Chain
Environment IBD), and the internal item flows -- each grounded in the behaviour
actually realised by the prototype.
"""
import subprocess

PART_FILL, PART_EDGE = "#f7f0d6", "#8a7f4a"
PORT_FILL, PORT_EDGE = "#cfe6cf", "#5f7a5f"

# key -> (part name, type, prototype realisation note)
PARTS = {
    "slm":  ("slm",  "SBOM Lifecycle Manager",          "build adapter; SBOM projection"),
    "cim":  ("cim",  "Cybersecurity Intelligence Manager", "version-aware CVE/VEX correlation"),
    "skm":  ("skm",  "Software Knowledge Manager",      "ontology + KG; OWL 2 RL; SHACL"),
    "aids": ("aids", "AI Decision Support Service",     "GraphRAG retrieval + LLM explanation"),
    "rs":   ("rs",   "Remediation Service",             "version-upgrade recommendation"),
    "aas":  ("aas",  "Assurance &amp; Attestation Service", "validation gate; attestation"),
}

# port id -> (label, side)
PORTS = {
    "p1": ("p1 : I_BuildMetadata", "L"),
    "p3": ("p3 : I_Intelligence", "L"),
    "p2": ("p2 : I_SBOM", "R"),
    "p4": ("p4 : I_Update", "R"),
    "p5": ("p5 : I_DeploymentFeedback", "R"),
    "p6": ("p6 : I_Governance", "R"),
}

# (src, dst, item flow label, constraint)
FLOWS = [
    # --- external delegation ---
    ("p1", "slm",  "Build Metadata\\n(manifest, versions)", True),
    ("p3", "cim",  "Vulnerability Intelligence\\n(CVE / CWE / VEX)", True),
    ("p5", "slm",  "Deployed Inventory", False),
    ("p6", "aas",  "Governance Policy", False),
    ("slm", "p2",  "SBOM\\n(SPDX / CycloneDX view)", True),
    ("aas", "p4",  "Verified Remediation", True),
    ("aids", "p6", "Risk Assessment", True),
    # --- internal item flows ---
    ("slm", "skm",  "Component & Build\\nAssertions (RDF)", True),
    ("skm", "cim",  "Component Inventory\\n(identity + version)", False),
    ("cim", "skm",  "Correlation Results\\n(Match, VEX, Severity)", True),
    ("skm", "aids", "Grounded Context\\nSubgraph", True),
    ("aids", "rs",  "Impact Analysis &\nAffected Component Set", True),
    ("rs", "aas",   "Proposed\\nRemediation Plan", True),
    ("skm", "aas",  "Graph Evidence\\n(SHACL conformance)", False),
    ("aas", "skm",  "Attestation Record", False),
]


def part_node(key):
    nm, ty, note = PARTS[key]
    lbl = (f'<<B>{nm} : {ty}</B><BR/>'
           f'<FONT POINT-SIZE="8"><I>{note}</I></FONT>>')
    return (f'    "{key}" [label={lbl}, shape=box, style="filled,dashed", '
            f'fillcolor="{PART_FILL}", color="{PART_EDGE}", penwidth=1.2];')


def build_dot():
    L = ['digraph IBD {',
         '  rankdir=TB; splines=spline; compound=true;',
         '  nodesep=0.55; ranksep=0.62; pad=0.35;',
         '  fontname="Helvetica";',
         '  node [fontname="Helvetica", fontsize=10, margin="0.16,0.09"];',
         '  edge [fontname="Helvetica", fontsize=8, color="#4a4a4a",'
         ' fontcolor="#2f2f2f", arrowsize=0.7];', '']

    # external ports (outside the frame)
    for pid, (lbl, _s) in PORTS.items():
        L.append(f'  "{pid}" [label="{lbl}", shape=box, style=filled,'
                 f' fillcolor="{PORT_FILL}", color="{PORT_EDGE}",'
                 f' fontsize=9, height=0.28];')
    L.append('')

    # the System of Interest frame
    L.append('  subgraph cluster_soi {')
    L.append('    label=<<B>ibd [Block] SBOM Lifecycle Governance System</B>'
             ' [ Internal Structure ]>;')
    L.append('    labeljust=l; fontsize=11; style=rounded;'
             ' color="#5a6b8a"; penwidth=1.6; margin=18;')
    for k in PARTS:
        L.append(part_node(k))
    L.append('  }')
    L.append('')

    for s, d, lab, con in FLOWS:
        c = "" if con else ", constraint=false"
        L.append(f'  "{s}" -> "{d}" [label="{lab}"{c}];')

    # keep port columns tidy
    L.append('  {rank=same; "p1"; "p3";}')
    L.append('  {rank=same; "p4"; "p6";}')   # remediation/governance exit at the bottom
    L.append('  {rank=same; "p2"; "p5";}')   # SBOM out / deployment feedback in
    L.append('}')
    return "\n".join(L)


if __name__ == "__main__":
    out = "../../fig_ibd_soi"
    with open(out + ".dot", "w") as f:
        f.write(build_dot())
    for fmt in ("png", "svg"):
        args = ["dot", f"-T{fmt}", out + ".dot", "-o", out + "." + fmt]
        if fmt == "png":
            args.insert(2, "-Gdpi=200")
        subprocess.run(args, check=True)
    print("wrote", out + ".png /.svg")
