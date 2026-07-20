"""Phase 5 — Yocto build adapter.

Turns a Yocto image manifest (NAME ARCH VERSION per line) into RDF facts:
one ssc:SoftwareComponent per package (version + purl), an ssc:FirmwareImage,
and an ssc:Build with PROV-O provenance. Output is Turtle.

The same code consumes a real `<image>.rootfs.manifest` from a bitbake build.
"""
import re
from datetime import datetime, timezone
from pathlib import Path
from rdflib import Graph, Namespace, Literal, RDF, XSD
from rdflib.namespace import RDFS, PROV

SSC  = Namespace("http://systemscyber.colostate.edu/ssc#")
DATA = Namespace("http://systemscyber.colostate.edu/ssc/data#")


def _slug(s):
    return re.sub(r"[^A-Za-z0-9]+", "_", s).strip("_")


def parse_manifest(path):
    """Yield (name, arch, version) tuples, skipping comments/blank lines."""
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 3:
            name, arch, version = parts[0], parts[1], parts[2]
            yield name, arch, version


def build_graph(manifest_path, image_name="uthp-scarthgap-image",
                build_id="build-scarthgap-508", builder="bitbake",
                timestamp=None):
    """Return an rdflib Graph of composition + provenance facts from a manifest."""
    g = Graph()
    g.bind("ssc", SSC); g.bind("", DATA); g.bind("prov", PROV)
    ts = timestamp or datetime.now(timezone.utc).replace(microsecond=0).isoformat()

    img   = DATA[_slug(image_name)]
    build = DATA[_slug(build_id)]
    agent = DATA[_slug(builder)]

    g.add((build, RDF.type, SSC.Build))
    g.add((build, SSC.hasTimestamp, Literal(ts, datatype=XSD.dateTime)))
    g.add((build, PROV.wasAssociatedWith, agent))
    g.add((img, RDF.type, SSC.FirmwareImage))
    g.add((img, SSC.producedBy, build))

    for name, arch, version in parse_manifest(manifest_path):
        ver = re.sub(r"-r\d+$", "", version)              # drop Yocto -rN suffix
        comp = DATA[f"pkg_{_slug(name)}_{_slug(ver)}"]
        g.add((comp, RDF.type, SSC.SoftwareComponent))
        g.add((comp, RDFS.label, Literal(f"{name} {ver}")))
        g.add((comp, SSC.hasVersion, Literal(ver, datatype=XSD.string)))
        g.add((comp, SSC.identifiedByPurl,
               Literal(f"pkg:generic/{name}@{ver}", datatype=XSD.anyURI)))
        g.add((comp, SSC.includedIn, img))
        g.add((comp, PROV.wasGeneratedBy, build))          # provenance: from this build
    return g


def generate(manifest_path, out_path, **kw):
    g = build_graph(manifest_path, **kw)
    g.serialize(destination=str(out_path), format="turtle")
    return out_path, len(g)


if __name__ == "__main__":
    import sys
    mp = sys.argv[1] if len(sys.argv) > 1 else "../data/uthp_image.rootfs.manifest"
    op = sys.argv[2] if len(sys.argv) > 2 else "../data/uthp_build.ttl"
    out, n = generate(mp, op)
    print(f"Wrote {n} triples to {out}")
