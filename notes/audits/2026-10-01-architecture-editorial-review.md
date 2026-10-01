# Architecture editorial and structural review

draft-mcguinness-mission-architecture at main `4853b1d7`. Review only;
nothing is applied. Line numbers (L) are the draft at that commit.
Inputs: one full read by the reviewer, one cold reader with no family
context (opus), and scripted density and repetition counts.

## Verdict

The content is worth keeping, and almost none of it needs to go. The
problems are structural, and the density is mostly a symptom of them.
Four causes:

1. **Too many frames, none placed.** The family is divided up ten ways:
   the verb spine, four reference stacks, five packages, the
   document-map groups, assurance levels, assurance claims, the
   binding-property vector, containment properties (which reuse the
   level names), three binding-architecture patterns, and R1-R19 plus
   eight Mission Context properties. Each frame re-lists the same
   documents, and nothing tells a reader which frame answers which
   question.
2. **Binding differences are narrated inline.** The prose is written
   in the OAuth realization, and almost every section then carries its
   AAuth, MAS, or UMA exception. AAuth appears 92 times in 13 of the 17
   top-level sections. The Binding Security Architectures table already
   holds most of these differences.
3. **Every claim carries its own disclaimers.** "The profile governs"
   is said 11 times, "not an eighth invariant" 3 times, and there are 53
   "not a"/", never" contrasts. Many of them negate readings no reader
   would form.
4. **The document's role is inconsistent.** It says it defines no
   protocol, object, or requirement (L398, L463). Yet it holds the
   family's only definition of the binding-property identifiers (L2819:
   "the family's authoritative definition"), the Baseline verification
   tests, and a Deployment Profile shape. About 37% of the body is
   deployment guidance rather than architecture.

Fixing the structure removes most of the repetition without cutting
substance. Each move below either gives a concept one home or relocates
it. Any removal is a duplicate of text that is kept elsewhere.

## Baseline

| Measure | Value |
| --- | --- |
| Body words | 22,585 across 56 units, 17 top-level sections |
| Paragraphs: count, median words, over 150 words | 382, 39, 11 (max 251) |
| Sentences over 40 / over 60 words | 116 / 24 |
| Largest units | Document Map 1,578; Assurance Levels 1,509; Binding Properties 1,486; Entry Ramps 1,118 |
| AAuth mentions | 92, in 13 of 17 top-level sections |
| "the OAuth binding" | 74, of which 21 are "(the OAuth binding's X section)" parentheticals |
| "not a" / ", never" contrasts | 30 / 23 |
| Uppercase BCP 14 in body | 4 (L539, L1960, L2877, L2879) |
| Section names other drafts cite | 3: Mission Binding Properties (core, MAS), the Approve verb (template), the MAS-mode sequence diagram (MAS) |
| Cited by | 23 drafts, all informatively; not in the ledger |

Recommendations keep every anchor and the three externally cited names.

## A. Defects: fix whatever the structure decisions

1. **"AuthZEN binding" appears 7 times** (L853, L1082, L1787, L1788,
   L2621, L2637, L2911), against #845's rule that "binding" names only
   the substrate bindings. The companion is the AuthZEN Profile, so
   these become "AuthZEN profile".
2. **"the four issuer bindings"** (L1117) versus "the five bindings"
   (L890).
3. **"eight primitives"** (L1772), but the table has six rows
   (L1785-1790). The other two are the Mission-Bound Credential and
   Approval Fidelity subsections. Either say so, or add both as table
   rows.
4. **"Mission-bound" is defined circularly.** Token Classes defers to
   Binding Properties (L1821-1823, L1833-1840), and Binding Properties
   points back to Token Classes (L2820). L1849 "condition 2 of
   `credential-mission-bound` above" refers to text about 1,000 lines
   below (L2829). "The OAuth binding publishes no Statement" is said
   twice (L1827-1831, L2823-2825).
5. **"an Action-Enforced deployment"** (L2398): no such level exists.
   The level is Runtime-Enforced.
6. **Terms used but never defined or pointed to:**
   - consequential action (8 uses; L506 only names its owner);
   - high-consequence classes (8 uses, first at L919);
   - Effective Authority Set (L962);
   - Enforcement Scope Statement (4 uses, first at L2669);
   - `decide_anew` (L2459);
   - "half-step" (used at L2554, defined at L2570).

   Add each to Conventions as "used as {{X}} defines it".
7. **AAuth's base protocol is never cited.** "AAuth", "PS", "R3", and
   "mission blob" appear from L408 with no expansion. Add the base
   reference (check its current name and revision live), and expand
   each term on first use.
8. **Uppercase keywords** in a document whose Conventions disclaim them:
   L539 "MAY propose", L1960 "MAY provide", L2877-2879 "SHOULD be ...
   OPTIONAL". The last two describe dependency rules. Lowercase them, or
   attribute them to the dependency.
9. **Temporal prose:**
   - L1979: "this checklist is now normatively stated";
   - L1766: "it is today the OAuth binding's";
   - L657 and L2939: "no family carrier supplies today";
   - L440: "no production Mission deployment is known today".
10. **Object-count collision.** "Four objects" (L529: Intent, Mission,
    Authority, Action) sits beside "Three Objects, Three Lifecycles"
    (L1624), which opens by apologizing for the collision. Retitle L1624
    (for example, "Agent Identity, Agent Deployment, and Mission") and
    keep its anchor.

## B. Repetition: one home each

| # | Concept | Stated at (L) | Home | Elsewhere |
| --- | --- | --- | --- | --- |
| 1 | Mission is not a new way to express authority | 386, 410-413, 535-537, 795-808 | Introduction, first paragraph | Non-Goals keeps the RAR, GNAP, and capability comparison; cut L535-537 |
| 2 | Delegated-authority layer | 387-390, 456-461, 578-601, 1541-1563 | The Mission, with the planes diagram moved there from Components | Abstract keeps one clause; cut L456-461 |
| 3 | Bindings: peer standing and differences | 421-454, 569-576, 783-789, 1139-1144, 1509-1539, 2091-2172, 2505-2522, 3314-3320 | Binding Security Architectures, moved up (C3) | A clause or table cell |
| 4 | Only `active` permits; unknown fails safe | 555-567, 1155-1160, 1786, 2599-2608, 3347-3350 | The invariant | Pointer |
| 5 | What survives revocation | 558-560, 648-650, 1186-1190, 2535-2549, 2739-2748, 3231-3232, 3239-3241, 3533-3538 | Validity Model | Pointer |
| 6 | Lifetime-bounded (TTL) reliance | 1937-1975, 2147-2151, 2190, 2219-2227, 2539-2549 | Validity Model | Baseline keeps one sentence; Short Mission keeps the pattern |
| 7 | The kernel list | 1749-1757, 1984-1998, 3272-3299 | Substrate introduction | Cut the Binding Checklist (its own L1979-1982 cedes to the substrate); Requirements 1-6 point |
| 8 | "Mission-bound" | 1806-1840, 1842-1881, 2818-2871 | Binding Properties | Token Classes keeps the three-term list and one pointer |
| 9 | Anchors commit, not semantics | 824-826, 1207-1212, 1793-1802, 2035-2050, 3542-3545 | Derivation Boundary | The invariant keeps its line |
| 10 | MAS has no token-layer kill switch | 1440-1443, 1853-1856, 2112, 2153-2166, 2512-2516, 2551-2559, 2735 | Binding Security Architectures | Pointer |
| 11 | Claims, not levels, are what relying parties compare | 2486-2494, 2752-2757, 2779-2782, 2979-2983, 3196-3200 | Assurance Claims | Cut |
| 12 | Four stacks are the four levels | 1065-1103, 2524-2672 | Assurance Levels (DRAFTS.md already calls the stacks "its Mission Assurance Levels") | Reference Architecture becomes one paragraph; anchor kept |
| 13 | A work product is input, not authority | 1231-1241, 2282-2295 | The invariants' readings | The quarantine pattern points to it |
| 14 | Delegation chooser | 991-998, 1733-1744 | Delegate verb | Swarm points to it |
| 15 | Issuance join | 1877-1881, 2168-2172, 2556-2559 | Binding Security Architectures | Pointer |
| 16 | Staleness bound + permit window + execution bound | 2621-2624, 2736, 2762-2765, 3256-3258 | Bounded Revocation Latency claim | Referred to by name |
| 17 | The five crossovers | list 2349-2380, table 2382-2388 | The table | Fold the list's caveats into a column |
| 18 | "The profile governs" | 398, 463-467, 498-500, 1773, 1238-1241, 1257-1260, 2483, 2577-2579, 2728-2730, 2992-2996, 3526 | Introduction L463-467 | Cut |
| 19 | Attribution is carried, never inferred | 1192-1199, 1608-1612 | Actor Chain | The invariant keeps one line |
| 20 | Per-verb owner lists | each verb subsection, Document Map, DRAFTS.md | The overlay table (C1) | Verb subsections keep the question and the boundary |

## C. Structure

### C1. Make the frames overlays on the verb spine

The verb spine is the family's signature view. Keep it as the frame and
make the others overlays on it. Do not regroup the verbs.

- Fold the four stacks into the levels (B12).
- At the verbs section, add one overlay table: verb, question, owning
  documents, and the first level that requires it. It replaces the
  owner lists in each verb subsection, which keep the question and the
  boundary.
- Open the assurance part with a five-row table of which frame answers
  which question:

  | Frame | Question it answers |
  | --- | --- |
  | Levels | What to deploy |
  | Claims | What a relying party can verify |
  | Binding properties | Whose Mission a path is bound to |
  | Containment properties | What a capability kill reaches |
  | Deployment Profile | Where all of it is declared |

  This is a density fix, not a restructure.

### C2. Order

The current order runs model, then deployment, then model again: the
derivation boundary comes after the substrate, and Requirements come
after deployment. There are also forward references. Capability
Envelope cites assurance levels, kill-switch composition, binding
properties, the ontology contract, and the Deployment Profile before any
of them appears. The Reference Architecture uses level names about 1,400
lines before the levels are introduced. The Ontology Contract says the
derivation boundary comes "later in this document" (L1264).

Proposed order:

1. **Introduction:** what a Mission is, why it exists, and what this
   document is. L436-461 moves to C3.
2. **Conventions and Terminology:** add the A6 terms, AAuth, and PS.
   Say once that, unless a passage names another binding, it describes
   the OAuth binding. That retires most of the 21 parentheticals.
3. **A Mission's Life:** the worked example comes first. Put the OAuth
   sequence (L757) and the MAS-mode sequence (L2229) side by side, and
   rename steps "Issue" and "Stop" to match the verbs.
4. **The Mission:** the object, the four objects, the lifecycle, and the
   layer thesis with the planes diagram. Capability Envelope is cut back
   to the envelope and its levers. The stance material (L659-688:
   structural signals, survivable incorrectness, least exposure) gets
   its own subsection. The open-world material (L690-708) moves to the
   ontology contract.
5. **Non-Goals.**
6. **Roles and Components:** includes the actor chain and the three
   lifecycles. Swarm Execution moves to the Delegate verb.
7. **The Mission Verbs:** with the C1 overlay table. The Continue
   paragraph (231 words) becomes question, boundary, owner, and a
   three-item list of the continuities.
8. **Mission Invariants:** the seven, plus one short "readings" list
   that replaces the four "Read as/against/on/under" paragraphs
   (L1214-1260).
9. **Meaning and Derivation:** the Ontology Contract, the Derivation
   Boundary, and Approval Fidelity together, covering who owns meaning,
   who commits authority, and what the anchors prove.
10. **The Substrate and the Bindings:**
    - the kernel;
    - the primitives table, made eight rows;
    - the Validity Model;
    - Token Classes;
    - Binding Security Architectures, as the one home for binding
      differences (C3).
11. **Assurance:**
    - the frames table;
    - the levels, absorbing the stacks;
    - claims;
    - binding properties;
    - kill-switch composition merged with the Containment Matrix
      (they overlap at L2704-2748 and L3223-3262);
    - prevention and detection.
12. **Deployment:**
    - entry ramps;
    - named pattern subsections (issuance-only, short mission,
      quarantine, standing agent; today all under one heading,
      L2174-2323);
    - the Deployment Profile.
13. **Security, Privacy, IANA.**

Appendix candidates:

- Requirements;
- Worked Composition;
- Comparison to a Conventional Stack (table form);
- Error Surfaces and Registration Posture (L2005-2031, wire detail
  inside a substrate summary);
- Verification Coverage by Level (L2577-2615; see D7);
- Document Map.

**Reader split.** The cold reader proposed the same skeleton, with three
differences:

- It moves Comparison into core's "Why a New Object". Core is the
  editor's draft and issue-first, and the comparison is positioning for
  the whole family, so this review keeps it here as an appendix.
- It demotes the Deployment Profile to an appendix (D2).
- It moves the kill-switch table into the containment profile (D6).

### C3. AAuth: one home, cited from each section

Gather the roughly 16 inline AAuth carve-outs into one home: "How the
AAuth binding realizes the model", under Binding Security Architectures.
Extend that section's table with rows for:

- invariants adopted;
- lifecycle states;
- approval fidelity;
- validity horizons;
- error surface;
- privacy posture.

Each section keeps a one-clause pointer only where the difference
changes the reader's conclusion. This is the cross-cutting-rule move,
not a demotion: it gives the peer binding a section of its own, the way
the OAuth realization already has the default prose. Expected effect:
AAuth mentions fall from 92 to about 35, and the eight densest
paragraphs lose their second model. Main carve-out sites:

- L408-410, L427-430, L448-451;
- L569-576, L785-789;
- L1139-1144, L1161-1167, L1459-1463;
- L1892-1895, L1916-1919;
- L2101-2104, L2131-2137;
- L2507-2510, L2518-2522, L2561-2566;
- L3314-3316.

## D. Density

- **Paragraphs to split** (over 130 words), one idea each:
  - L1704-1731, Swarm (240 words);
  - L1015-1044, Continue (231);
  - L2196-2217, issuance-only (178);
  - L1324-1348, direction axis (175);
  - L3139-3159, `key_custody` (168);
  - L2979-2996, Deployment Profile opening (165);
  - L436-454, peer standing (162);
  - L2035-2050 and L2056-2071, derivation (149 each);
  - L1243-1260, composition reading (139);
  - L981-998, Delegate (138);
  - L1264-1279, ontology opening (135);
  - L925-948, Govern (134).
- **Long sentences:** the 24 sentences over 60 words. Use one claim per
  sentence, and state the condition before the claim.
- **Tables with prose cells:**
  - The kill-switch composition cells run 100 to 200 words
    (L2734-2737). Use short cells with numbered notes, or one paragraph
    per row.
  - The mechanism mapping (L2942-2956) is a single 120-word sentence.
    Make it a two-column table: mechanism, property.
  - The Agent entry (L1403-1418) is a 110-word aside on instance
    identity inside a role definition. Cut it to one sentence and a
    pointer.
- **Meta-commentary to cut:**
  - "not an eighth invariant" (3 times);
  - "that section, not this summary, is the normative text" (2 times);
  - "Every cell is informative and carries no RFC 2119 language"
    (L2728);
  - "The table is the one-page answer" (L2117);
  - "Two classifications make the example honest" (L2458).
- **Contrasts:** keep the ones that block a real misreading ("a
  continuation handle grants nothing"). Cut the ones that negate a
  reading nobody would form.

## E. Decisions for the author

- **D1. Binding Properties (L2784-2975).** This is the only definition
  of the vector in the family: 20 identifier uses here, and 3 in core
  and MAS, both informative. It calls itself authoritative (L2819) and
  "stable identifiers" (L2958) in a document that defines no object.
  Options:
  - (a) Keep it here, and change the Introduction's scope sentence to
    say the document defines descriptive vocabulary (binding
    properties, token classes, assurance levels) but no protocol or
    requirement. No other document changes.
  - (b) Move it to the substrate draft. This is a family round:
    re-point core and MAS, and decide whether it gets ledger rows.
  - (c) Move it to the runtime profile, which owns the Enforcement
    Scope Statement that carries the per-path declarations.
- **D2. Deployment Profile (L2977-3200, 888 words, two JSON shapes).**
  Its schema is deliberately deferred. Moving the shapes to an appendix
  shortens the body without touching that reservation. Is the body
  placement deliberate?
- **D3. Document Map (1,578 words).** It duplicates DRAFTS.md, but
  DRAFTS.md is not part of the I-D, so a map inside the draft has value.
  Options:
  - trim each role to 15 words or fewer and move the map to an
    appendix;
  - generate it from `family-manifest.json`, the way DRAFTS.md's
    reference-stacks table is generated.
- **D4. Five Packages (L1105-1129).** A third taxonomy that admits the
  document map is the maintained assignment (L1109). DRAFTS.md
  deliberately does not restate it. Either make it a column in the C1
  overlay table, or cut it.
- **D5. Requirements (L3264-3395).** They restate the kernel and the
  invariants. No other draft cites an R-number, so a move is free. Keep
  them in the body, or move them to an appendix?
- **D6. The level names collide with the containment properties
  (L2706-2718).** A paragraph explains that "Baseline" and
  "Runtime-Enforced" each mean two things. The fix belongs in the
  containment profile, by renaming its properties (for example,
  derivation-gated and action-gated), or the collision stays and gets
  explained once.
- **D7. Verification coverage inside Baseline Issuance (L2577-2615).**
  It is checked: neither the substrate draft nor core states these
  tests, and no ledger row matches them one-to-one. So they cannot be
  cut to a pointer without losing content. Move them to an appendix
  here, or into the substrate's conformance material in a family round.
- **D8. Comparison to a Conventional Stack.** Keep it as an appendix
  here (table form), or move it into core's "Why a New Object" through
  an issue.

## F. Application plan

Three PRs, in order, each provable:

1. **Defects and one-home deduplication (A, B).** No reordering.
   - Proof: the BCP 14 sequence is unchanged apart from the A8
     lowercasing, and every anchor and the three cited names are kept.
   - Then a cold consistency read for pointers whose target no longer
     says what the citing sentence claims.
   - Rough deltas: Binding Checklist -165 words, crossover list -240,
     Token Classes and Credential about -300, disclaimers and
     meta-commentary about -350, AAuth consolidation net about -500.
2. **Structure (C), with D1-D8 applied as ruled.** A scripted
   reassembly with `spec_units.py`, anchors unchanged. Regenerate the
   DRAFTS.md row summary.
3. **Density (D).** Section owners work in parallel within a fixed word
   budget, followed by a condition verifier.

The total falls out of these moves. No figure is promised.
