# ontology-ssc

Executable OWL ontology for the SBOM Lifecycle Governance reference architecture (UTHP/Yocto prototype).

## Files
- `ssc.ttl` — the ontology (OWL, Turtle serialization), v0.1. Traces to the design in `../ontology_phase1.md`.

## What's inside
- Composition (SoftwareComponent, Build, FirmwareImage, Supplier, License)
- Deployment/CPS (TargetDevice + subtypes, ECU, VehicleNetwork, VehicleFunction/SafetyFunction)
- Intelligence (Vulnerability, Weakness, VEXStatement)
- Analysis/governance (ComponentVulnerabilityMatch, RiskAssessment, Remediation, Attestation, Evidence)
- Controlled values (VEXStatus, MatchMethod, Severity, RiskLevel)
- Inference: `dependsOn` (transitive) → CQ2; `runsOn` and `mayImpactFunction` property chains → CQ10 (network-mediated safety impact)

## Load / reason
**Protégé:** File → Open `ssc.ttl`; start a reasoner (e.g., HermiT/ELK) to see inferred `runsOn` / `mayImpactFunction`.

**Python (offline, no server):**
```
pip install rdflib owlrl pyshacl
```
```python
from rdflib import Graph
import owlrl
g = Graph().parse("ssc.ttl", format="turtle")
owlrl.DeductiveClosure(owlrl.OWLRL_Semantics).expand(g)   # materialize inferences
print(len(g), "triples after inference")
```

## Usage examples (how to write facts)
Schema terms use `ssc:`; instances use a data namespace.

```turtle
@prefix ssc:  <http://systemscyber.colostate.edu/ssc#> .
@prefix :     <http://systemscyber.colostate.edu/ssc/data#> .
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
@prefix prov: <http://www.w3.org/ns/prov#> .
@prefix xsd:  <http://www.w3.org/2001/XMLSchema#> .

# 1. A software component (identity + version + supplier + license)
:zlib_1_2_11 a ssc:SoftwareComponent ;
    ssc:hasVersion "1.2.11" ;
    ssc:identifiedByPurl "pkg:generic/zlib@1.2.11"^^xsd:anyURI ;
    ssc:suppliedBy :zlib_project ;
    ssc:license   :Zlib_License .

# 2. Composition
:app_ivi        ssc:dependsOn  :openssl_3_0_12 .
:openssl_3_0_12 ssc:dependsOn  :zlib_1_2_11 .        # transitive: app_ivi -> zlib is inferred
:zlib_1_2_11    ssc:includedIn :ivi_image_104 .      # component is part of an image

# 3. Build provenance + deployment + the impact-pivot path
:ivi_image_104 a ssc:FirmwareImage ;
    ssc:producedBy :yocto_build_104 ;
    ssc:deployedOn :head_unit .
:yocto_build_104 a ssc:Build ; ssc:hasTimestamp "2026-07-15T09:00:00Z"^^xsd:dateTime .
:head_unit a ssc:InfotainmentUnit ; ssc:connectsTo :can_bus .
:can_bus   a ssc:VehicleNetwork   ; ssc:reaches    :brake_ecu .
:brake_ecu a ssc:ECU              ; ssc:supports   :braking .
:braking   a ssc:SafetyFunction .
# Reasoner infers:  :zlib_1_2_11 ssc:runsOn :head_unit  AND  :zlib_1_2_11 ssc:mayImpactFunction :braking

# 4. A vulnerability, and the WEAKNESS it exploits
:CVE-2022-37434 a ssc:Vulnerability ;
    ssc:hasSeverity  ssc:Critical ;
    ssc:hasCvssScore 9.8 ;
    ssc:hasWeakness  :CWE-787 .          # <-- "which weakness is exploited in a CVE"
:CWE-787 a ssc:Weakness ; rdfs:label "Out-of-bounds Write" .

# 5. Linking a VULNERABILITY to a COMPONENT  (use the reified Match, NOT a direct edge)
:match_zlib_cve a ssc:ComponentVulnerabilityMatch ;
    ssc:matchesComponent     :zlib_1_2_11 ;
    ssc:matchesVulnerability :CVE-2022-37434 ;
    ssc:matchMethod          ssc:ExactIdentifier ;
    ssc:hasConfidence        1.0 ;
    ssc:hasVEXStatus         :vex_zlib_cve .
:vex_zlib_cve a ssc:VEXStatement ; ssc:vexStatus ssc:Affected .

# 6. Risk assessment backed by evidence
:risk_001 a ssc:RiskAssessment ;
    ssc:assesses     :match_zlib_cve ;
    ssc:hasRiskLevel ssc:RiskHigh ;
    ssc:supportedBy  :evidence_nvd .
:evidence_nvd a ssc:Evidence ;
    ssc:hasTimestamp "2026-07-15T10:00:00Z"^^xsd:dateTime ;
    prov:wasAttributedTo :nvd_feed .

# 7. Remediation + attestation
:CVE-2022-37434 ssc:remediatedBy :fix_bump_zlib .
:fix_bump_zlib a ssc:Remediation ; rdfs:label "Bump zlib recipe to 1.2.13" ;
    ssc:attestedBy :attest_001 .
```

### Which property do I use?
| To state that… | Use |
|---|---|
| Component A depends on Component B | `ssc:dependsOn` (transitive) |
| Component is part of an image | `ssc:includedIn` |
| Image was built by a build | `ssc:producedBy` (+ `ssc:hasTimestamp` on the Build) |
| Image runs on a device | `ssc:deployedOn` |
| Device→network→ECU→function (impact path) | `ssc:connectsTo` / `ssc:reaches` / `ssc:supports` |
| **A CVE exploits a CWE** | **`ssc:hasWeakness`** (Vulnerability → Weakness) |
| **A component is affected by a vulnerability** | **create a `ssc:ComponentVulnerabilityMatch`** with `ssc:matchesComponent` + `ssc:matchesVulnerability` |
| Match confidence / method | `ssc:hasConfidence` / `ssc:matchMethod` |
| Exploitability status | `ssc:hasVEXStatus` → `ssc:vexStatus` |
| Risk of a match | `ssc:RiskAssessment` with `ssc:assesses` + `ssc:hasRiskLevel` + `ssc:supportedBy` |

**Key point:** there is **no direct "affectedBy" edge**. A Component↔Vulnerability link is always mediated by a `ComponentVulnerabilityMatch`, so every match records *how* it was matched, *how confident* it is, and its *VEX* status — that is what gives you provenance and lets you suppress false positives. (Optional shortcut for later: an inferred `ssc:affectedBy` via `owl:propertyChainAxiom ( [ owl:inverseOf ssc:matchesComponent ] ssc:matchesVulnerability )`.)

## Notes
- External vocabularies (SPDX, PROV-O) are referenced by alignment (`rdfs:subClassOf` / `rdfs:seeAlso`), **not** `owl:imports`, so the file loads without network access. Add `owl:imports` later if you want full external axioms.
- Property chains assume OWL 2 (RL is sufficient for the prototype).

## Next
- Phase 2: `../` seed dataset (`data/seed.ttl`) exercising App→LibA→LibB + one CVE.
- Phase 3: SHACL shapes (`shapes/ssc-shapes.ttl`).
- Phase 4: SPARQL queries for the competency questions.
