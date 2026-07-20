"""Render the instantiated knowledge graph as a node-link image.

Loads ontology + build + context + intelligence, materializes inference, and draws
the instance graph with networkx/matplotlib: nodes coloured by ontology type,
inferred `mayImpactFunction` edges highlighted. Saves PNG + SVG.
"""
from rdflib import Graph, RDF, RDFS, URIRef
import owlrl
import networkx as nx
import matplotlib.pyplot as plt

SSC = "http://systemscyber.colostate.edu/ssc#"

EDGE_PREDS = {"includedIn", "dependsOn", "deployedOn", "connectsTo", "reaches",
              "supports", "matchesComponent", "matchesVulnerability", "hasWeakness",
              "hasVEXStatus", "vexStatus", "mayImpactFunction"}
INFERRED = {"mayImpactFunction"}

COLOR = {
    "SoftwareComponent": "#4a86c5", "FirmwareImage": "#79b0e0", "Gateway": "#3fae9f",
    "VehicleNetwork": "#2f8f7f", "ECU": "#b5651d", "SafetyFunction": "#b22222",
    "Vulnerability": "#d9534f", "Weakness": "#8e6bc0",
    "ComponentVulnerabilityMatch": "#3aa76d", "VEXStatement": "#e0a83a",
}
DEFAULT = "#9aa0a6"


def local(u):
    return str(u).split("#")[-1].split("/")[-1]


def load(files, onto):
    g = Graph(); g.parse(onto)
    for f in files:
        g.parse(f)
    owlrl.DeductiveClosure(owlrl.OWLRL_Semantics).expand(g)
    return g


def node_type(g, n):
    for o in g.objects(n, RDF.type):
        if local(o) in COLOR:
            return local(o)
    return None


def label(g, n):
    lbl = g.value(n, RDFS.label)
    return str(lbl) if lbl else local(n).replace("pkg_", "").replace("_", " ")


def layered_pos(g, G):
    """Deterministic, publication-quality layout.

    A left-to-right deployment/safety backbone (component -> firmware -> gateway
    -> network -> ECU -> function); each component's vulnerability evidence chain
    (match -> CVE -> CWE and match -> VEX -> status) fans out to the left in its
    own horizontal band. Shared nodes are placed at the midpoint of their uses.
    """
    def S(x):
        return URIRef(SSC + x)
    Comp = S("SoftwareComponent")
    comps = sorted((n for n in G.nodes() if (n, RDF.type, Comp) in g),
                   key=lambda n: label(g, n))
    pos = {}

    def place(n, x, y):
        if n is None or n not in G or n in pos:
            return                         # first placement wins (shared nodes kept)
        pos[n] = (x, y)

    n = max(len(comps), 1)
    band = 5.0
    ys = [(n - 1) / 2.0 * band - i * band for i in range(len(comps))]
    for c, yc in zip(comps, ys):
        place(c, 5.8, yc)
        m = next((s for s in g.subjects(S("matchesComponent"), c) if s in G), None)
        place(m, 4.0, yc)
        cve = g.value(m, S("matchesVulnerability")) if m else None
        place(cve, 2.2, yc + 1.25)
        if cve is not None:
            for w in g.objects(cve, S("hasWeakness")):
                place(w, 0.0, yc + 1.25)
                break
        vex = g.value(m, S("hasVEXStatus")) if m else None
        place(vex, 2.2, yc - 1.25)
        if vex is not None:
            place(g.value(vex, S("vexStatus")), 0.0, yc - 1.25)

    # backbone (evenly spaced along y = 0)
    img = next((o for c in comps for o in g.objects(c, S("includedIn"))), None)
    place(img, 7.7, 0.0)
    gw = g.value(img, S("deployedOn")) if img else None
    place(gw, 9.4, 0.0)
    can = g.value(gw, S("connectsTo")) if gw else None
    place(can, 11.1, 0.0)
    ecu = g.value(can, S("reaches")) if can else None
    place(ecu, 12.8, 0.0)
    place(g.value(ecu, S("supports")) if ecu else None, 14.5, 0.0)

    for nd in G.nodes():                    # safety net for anything unplaced
        if nd not in pos:
            place(nd, 5.0, band * n)
    return pos


def draw(g, out_png, focus_affected=True, only_matched_components=True):
    Comp = URIRef(SSC + "SoftwareComponent")
    # components that are AFFECTED (for filtering the inferred impact edges)
    affected = set()
    matched = set()   # any component that participates in a correlation match
    for m in g.subjects(RDF.type, URIRef(SSC + "ComponentVulnerabilityMatch")):
        c = g.value(m, URIRef(SSC + "matchesComponent"))
        if c:
            matched.add(c)
        vex = g.value(m, URIRef(SSC + "hasVEXStatus"))
        if vex and g.value(vex, URIRef(SSC + "vexStatus")) == URIRef(SSC + "Affected"):
            if c:
                affected.add(c)

    def drop(n):
        # in focused mode, hide components that never matched a CVE (readability)
        return (only_matched_components and (n, RDF.type, Comp) in g
                and n not in matched)

    G = nx.DiGraph()
    normal, inferred = [], []
    epred = {}   # (s, o) -> property (predicate) name, for edge labels
    for s, p, o in g:
        if not (isinstance(s, URIRef) and isinstance(o, URIRef)):
            continue
        pl = local(p)
        if pl not in EDGE_PREDS:
            continue
        if drop(s) or drop(o):
            continue
        if pl in INFERRED and focus_affected and s not in affected:
            continue  # draw impact edges only for affected components (readability)
        G.add_edge(s, o)
        epred[(s, o)] = pl
        (inferred if pl in INFERRED else normal).append((s, o))

    colors = [COLOR.get(node_type(g, n), DEFAULT) for n in G.nodes()]
    SHORT = {"ComponentVulnerabilityMatch": "Match", "VEXStatement": "VEX"}

    def disp(n):   # don't repeat adjacent-node names on the match/VEX nodes
        return SHORT.get(node_type(g, n), label(g, n))
    labels = {n: disp(n) for n in G.nodes()}
    # deterministic, structured layout (backbone + per-vulnerability bands)
    pos = layered_pos(g, G)

    plt.figure(figsize=(22, 12))
    nx.draw_networkx_edges(G, pos, edgelist=normal, edge_color="#8f9296",
                           width=1.1, arrows=True, arrowsize=11, alpha=0.7,
                           node_size=1500, min_source_margin=16, min_target_margin=16)
    # inferred impact edges bowed away from the backbone so they stay readable
    nx.draw_networkx_edges(G, pos, edgelist=inferred, edge_color="#b22222",
                           width=2.0, style="dashed", arrows=True, arrowsize=15,
                           node_size=1500, min_source_margin=16, min_target_margin=16,
                           connectionstyle="arc3,rad=-0.28")
    nx.draw_networkx_nodes(G, pos, node_color=colors, node_size=1500,
                           edgecolors="#2b2b2b", linewidths=1.0)

    # ---- edge property labels (white bbox so they read over the lines) ----
    bbox = dict(boxstyle="round,pad=0.18", fc="white", ec="#dddddd", alpha=0.92)
    nx.draw_networkx_edge_labels(G, pos, edge_labels={e: epred[e] for e in normal},
                                 font_size=8.5, font_color="#3a3a3a",
                                 label_pos=0.5, rotate=False, bbox=bbox)
    # one label for the inferred relation (placed near the source), in red
    if inferred:
        sx, sy = pos[inferred[0][0]]
        tx, ty = pos[inferred[0][1]]
        plt.text(0.62 * sx + 0.38 * tx, 0.62 * sy + 0.38 * ty - 0.35,
                 "mayImpactFunction", color="#b22222", fontsize=9,
                 fontweight="bold", ha="center", va="center", bbox=bbox)

    # node labels: leftmost terminals (CWE / status) flush-left of the node;
    # everything else centered above, to keep long names from colliding.
    xmin = min(x for x, _ in pos.values())
    lbox = dict(boxstyle="round,pad=0.14", fc="white", ec="none", alpha=0.8)
    for nd, (x, y) in pos.items():
        if abs(x - xmin) < 1e-6:
            plt.text(x - 0.55, y, labels[nd], fontsize=9, fontweight="bold",
                     color="#111", ha="right", va="center", bbox=lbox)
        else:
            plt.text(x, y + 0.55, labels[nd], fontsize=9, fontweight="bold",
                     color="#111", ha="center", va="bottom", bbox=lbox)
    plt.margins(0.14)

    # legend
    from matplotlib.lines import Line2D
    leg = [Line2D([0], [0], marker="o", color="w", markerfacecolor=c, markersize=9, label=t)
           for t, c in [("Component", "#4a86c5"), ("Firmware image", "#79b0e0"),
                        ("Device / Network", "#3fae9f"), ("ECU", "#b5651d"),
                        ("Safety function", "#b22222"), ("Vulnerability", "#d9534f"),
                        ("Weakness", "#8e6bc0"), ("Match", "#3aa76d"), ("VEX status", "#e0a83a")]]
    leg.append(Line2D([0], [0], color="#b22222", lw=1.7, ls="--", label="mayImpactFunction (inferred)"))
    plt.legend(handles=leg, loc="lower left", fontsize=8, frameon=False, ncol=2)
    plt.axis("off"); plt.tight_layout()
    plt.savefig(out_png, dpi=300, bbox_inches="tight")
    plt.savefig(out_png.replace(".png", ".svg"), bbox_inches="tight")
    return G.number_of_nodes(), G.number_of_edges()


if __name__ == "__main__":
    g = load(["../data/uthp_build.ttl", "../data/uthp_context.ttl", "../data/uthp_intel.ttl"],
             "../ontology-ssc/ssc.ttl")
    n, e = draw(g, "../../fig_kg_graph.png")
    print(f"drew {n} nodes, {e} edges")
