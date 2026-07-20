"""Generate the SysML-style activity diagram with swimlanes (activity partitions)
for Section 4.3.4 Functional Allocation.

Each swimlane is one part of the SBOM Lifecycle Governance System; every activity
sits in the lane of the part to which the function is allocated. Object flows are
labelled with the information carried, so the diagram shows how information moves
through the allocated functions to deliver the system service.
"""
import textwrap
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch, Polygon, Circle, Rectangle

# ---------------------------------------------------------------- lanes
LANES = [  # (key, label, colour)
    ("slm",  "slm : SBOM\nLifecycle Manager",            "#dfe7f2"),
    ("cim",  "cim : Cybersecurity\nIntelligence Manager", "#e6f0e6"),
    ("skm",  "skm : Software\nKnowledge Manager",        "#f7f0d6"),
    ("aids", "aids : AI Decision\nSupport Service",      "#f0e2ef"),
    ("rs",   "rs : Remediation\nService",                "#e9e3f5"),
    ("aas",  "aas : Assurance &\nAttestation Service",   "#f6e3dd"),
]
LANE_H = 2.0
LY = {k: (len(LANES) - 1 - i) * LANE_H for i, (k, _l, _c) in enumerate(LANES)}

C = {i: 1.5 + 2.95 * (i - 1) for i in range(1, 12)}   # column x positions

BW, BH = 2.02, 1.02          # activity box size

# id -> (x, y, text, kind)
NODES = {
    "s1":  (0.30, LY["slm"],  "",                                   "start"),
    "s2":  (0.30, LY["cim"],  "",                                   "start"),
    "A1":  (C[1], LY["slm"],  "Ingest and Normalise Build Metadata", "act"),
    "A3":  (C[1], LY["cim"],  "Ingest Vulnerability Intelligence",  "act"),
    "A6":  (C[2], LY["skm"],  "Assert Facts into Knowledge Graph",  "act"),
    "A5":  (C[3], LY["cim"],  "Correlate Advisories to Components", "act"),
    "A7":  (C[4], LY["skm"],  "Materialise Inference and Validate", "act"),
    "A9":  (C[5], LY["skm"],  "Retrieve Grounded Context",          "act"),
    "A10": (C[6], LY["aids"], "Analyse Vulnerability Impact",       "act"),
    "A13": (C[7], LY["rs"],   "Propose Remediation Plan",           "act"),
    "A12": (C[7], LY["slm"],  "Project SBOM View",                  "act"),
    "A14": (C[8], LY["aas"],  "Evaluate Against Governance Policy", "act"),
    "D1":  (C[9] - 0.3, LY["aas"], "Conforms?",                     "dec"),
    "A15": (C[10] - 0.4, LY["aas"], "Attest and Release Update",    "act"),
    "e1":  (C[10] + 1.9, LY["aas"],  "Verified\nRemediation (p4)",  "end"),
    "e2":  (C[9] - 0.3, LY["slm"],   "SBOM (p2)",                   "end"),
    "e3":  (C[9] - 0.3, LY["aids"],  "Risk\nAssessment (p6)",       "end"),
}

# (src, src_side, dst, dst_side, label, rad, dashed)
ARROWS = [
    ("s1", "r", "A1", "l", "", 0, False),
    ("s2", "r", "A3", "l", "", 0, False),
    ("A1", "b", "A6", "l", "Component Assertions (RDF)", -0.16, False),
    ("A3", "r", "A5", "l", "Vulnerability Intelligence\n(CVE / CWE / VEX)", 0, False),
    ("A6", "t", "A5", "b", "Component Inventory", 0.18, False),
    ("A5", "b", "A7", "l", "Match / VEX / Severity", -0.16, False),
    ("A7", "r", "A9", "l", "Inferred Impact Paths", 0, False),
    ("A9", "b", "A10", "l", "Grounded Subgraph", -0.16, False),
    ("A10", "b", "A13", "l", "Impact Analysis &\nAffected Set", -0.16, False),
    ("A13", "b", "A14", "l", "Remediation Plan", -0.16, False),
    ("A14", "r", "D1", "l", "", 0, False),
    ("D1", "r", "A15", "l", "[conforms]", 0, False),
    ("D1", "t", "A13", "r", "[non-conforming]", 0.30, False),
    ("A15", "r", "e1", "l", "", 0, False),
    ("A7", "t", "A12", "b", "Canonical Graph", -0.16, False),
    ("A12", "r", "e2", "l", "", 0, False),
    ("A10", "r", "e3", "l", "", 0, False),
    ("A15", "t", "A7", "r", "Attestation Record", -0.40, True),
]

X0, X1 = -4.6, C[10] + 3.4

# manual nudges where a midpoint label would collide with a box
LBL_OFF = {("A1", "A6"): (1.15, -0.30), ("A7", "A9"): (0.0, 0.16),
           ("A6", "A5"): (-0.15, -0.10)}


def anchor(nid, side):
    x, y, _t, kind = NODES[nid]
    if kind in ("start", "end"):
        r = 0.20
        return {"l": (x - r, y), "r": (x + r, y), "t": (x, y + r), "b": (x, y - r)}[side]
    if kind == "dec":
        w, h = 1.30, 0.86
        return {"l": (x - w / 2, y), "r": (x + w / 2, y),
                "t": (x, y + h / 2), "b": (x, y - h / 2)}[side]
    return {"l": (x - BW / 2, y), "r": (x + BW / 2, y),
            "t": (x, y + BH / 2), "b": (x, y - BH / 2)}[side]


def draw():
    fig, ax = plt.subplots(figsize=(23, 9.5))

    # ---- swimlanes ----
    for k, label, colour in LANES:
        y = LY[k]
        ax.add_patch(Rectangle((X0, y - LANE_H / 2), X1 - X0, LANE_H,
                               facecolor=colour, edgecolor="#8a8a8a",
                               linewidth=0.9, zorder=0))
        ax.add_patch(Rectangle((X0, y - LANE_H / 2), 4.15, LANE_H,
                               facecolor="white", alpha=0.55,
                               edgecolor="#8a8a8a", linewidth=0.9, zorder=1))
        ax.text(X0 + 2.07, y, label, ha="center", va="center",
                fontsize=10, fontweight="bold", color="#1a1a1a", zorder=2)

    # ---- nodes ----
    for nid, (x, y, txt, kind) in NODES.items():
        if kind == "start":
            ax.add_patch(Circle((x, y), 0.20, facecolor="#1a1a1a",
                                edgecolor="#1a1a1a", zorder=4))
        elif kind == "end":
            ax.add_patch(Circle((x, y), 0.24, facecolor="white",
                                edgecolor="#1a1a1a", linewidth=1.6, zorder=4))
            ax.add_patch(Circle((x, y), 0.13, facecolor="#1a1a1a", zorder=5))
            ax.text(x, y - 0.46, txt, ha="center", va="top", fontsize=8.5,
                    fontweight="bold", color="#111", zorder=5)
        elif kind == "dec":
            w, h = 1.30, 0.86
            ax.add_patch(Polygon([(x, y + h / 2), (x + w / 2, y),
                                  (x, y - h / 2), (x - w / 2, y)],
                                 closed=True, facecolor="#ffffff",
                                 edgecolor="#333", linewidth=1.2, zorder=4))
            ax.text(x, y, txt, ha="center", va="center", fontsize=8, zorder=5)
        else:
            ax.add_patch(FancyBboxPatch((x - BW / 2, y - BH / 2), BW, BH,
                                        boxstyle="round,pad=0.02,rounding_size=0.16",
                                        facecolor="white", edgecolor="#333",
                                        linewidth=1.2, zorder=4))
            ax.text(x, y, textwrap.fill(txt, 20), ha="center", va="center",
                    fontsize=8.4, zorder=5)

    # ---- arrows ----
    for s, ss, d, ds, lab, rad, dashed in ARROWS:
        p0, p1 = anchor(s, ss), anchor(d, ds)
        ax.add_patch(FancyArrowPatch(
            p0, p1, connectionstyle=f"arc3,rad={rad}",
            arrowstyle="-|>", mutation_scale=12,
            linewidth=1.25, linestyle="--" if dashed else "-",
            color="#b22222" if dashed else "#333", zorder=3,
            shrinkA=0, shrinkB=0))
        if lab:
            mx, my = (p0[0] + p1[0]) / 2, (p0[1] + p1[1]) / 2
            my += 0.30 if abs(p1[1] - p0[1]) < 0.1 else 0.0
            mx += -0.55 * rad * (p1[1] - p0[1])
            ox, oy = LBL_OFF.get((s, d), (0.0, 0.0))
            mx, my = mx + ox, my + oy
            ax.text(mx, my, lab, ha="center", va="center", fontsize=7.4,
                    color="#b22222" if dashed else "#333",
                    bbox=dict(boxstyle="round,pad=0.16", fc="white",
                              ec="none", alpha=0.9), zorder=6)

    ax.set_xlim(X0 - 0.3, X1 + 0.3)
    ax.set_ylim(-LANE_H / 2 - 0.9, LY["slm"] + LANE_H / 2 + 0.5)
    ax.axis("off")
    plt.tight_layout()
    for ext in ("png", "svg"):
        plt.savefig(f"../../fig_activity_allocation.{ext}",
                    dpi=250 if ext == "png" else None, bbox_inches="tight")
    print("wrote fig_activity_allocation.png /.svg")


if __name__ == "__main__":
    draw()
