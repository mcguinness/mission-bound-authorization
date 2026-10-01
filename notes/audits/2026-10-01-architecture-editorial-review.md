# Architecture editorial and structural review

draft-mcguinness-mission-architecture at main `4853b1d7`. Review only;
nothing is applied. Line numbers (L) are the draft at that commit.

Inputs:
- one full read by the reviewer;
- one cold reader with no family context (opus);
- scripted density and repetition counts;
- a second-model review of this plan (2026-10-01).

The second-model review changed the plan in seven ways:
- added A1, a containment inconsistency, and A11;
- reclassified the issuer-bindings count (A2) and the "circular"
  definition (A4);
- dropped the implicit-OAuth convention and the AAuth reduction target;
- deduplication now keeps local qualifications;
- the verification tests are traced to their owners, not owned here;
- the PR order changed;
- reader checks were added as acceptance criteria.

## Verdict

The content is worth keeping, and almost none of it needs to go. One
passage is wrong (A1). The rest of the problem is structural, and the
density is mostly a symptom of it. Four causes:

1. **Too many frames, none placed.** The family is divided up ten ways:
   the verb spine, four reference stacks, five packages, the
   document-map groups, assurance levels, assurance claims, the
   binding-property vector, containment properties (which reuse the
   level names), three binding-architecture patterns, and R1-R19 plus
   eight Mission Context properties. Each frame re-lists the same
   documents, and nothing tells a reader which frame answers which
   question. The frames answer different questions and should stay
   distinct. What is missing is the placement.
2. **Binding differences are narrated inline.** The prose is mostly
   written in the OAuth realization, and nearly every section then adds
   its AAuth, MAS, or UMA exception. AAuth appears 92 times in 13 of the
   17 top-level sections. Some of those qualifications change a
   guarantee (issuance gating, authority projection, termination effect)
   and must stay beside the claim. The rest restate the Binding Security
   Architectures table.
3. **Every claim carries its own disclaimers.** "The profile governs"
   is said 11 times, "not an eighth invariant" 3 times, and there are 53
   "not a"/", never" contrasts. Many of them negate readings no reader
   would form.
4. **Readers cannot tell what kind of statement they are reading.**
   Three kinds of material sit side by side with no labels:
   - vocabulary this document defines (binding properties, token
     classes, assurance levels);
   - illustrative material (the Deployment Profile shapes, the worked
     composition, the verification scenarios);
   - rules owned by other documents.

   The sharpest case: L2819 calls Binding Properties "the family's
   authoritative definition", while L398 and L463 say the document
   defines no object. Deployment guidance belongs in an architecture
   document. The problem is the missing labels, not the guidance.

The structural fixes remove most of the repetition without cutting
substance. Each move below either gives a concept one authoritative
explanation or relocates it. A repetition that carries a distinct
condition (binding, actor, action path, timing, or residual) keeps a
short qualified summary beside the claim it constrains (B).

## Baseline

| Measure | Value |
| --- | --- |
| Body words | 22,585 across 56 units, 17 top-level sections |
| Paragraphs: count, median words, over 150 words | 382, 39, 11 (max 251) |
| Sentences over 40 / over 60 words | 116 / 24 |
| Largest units | Document Map 1,578; Assurance Levels 1,509; Binding Properties 1,486; Entry Ramps 1,118 |
| AAuth mentions | 92, in 13 of 17 top-level sections (diagnostic, not a target) |
| "the OAuth binding" | 74, of which 21 are "(the OAuth binding's X section)" parentheticals |
| "not a" / ", never" contrasts | 30 / 23 |
| Uppercase BCP 14 in body | 4 (L539, L1960, L2877, L2879) |
| Section names other drafts cite | 3: Mission Binding Properties (core, MAS), the Approve verb (template), the MAS-mode sequence diagram (MAS) |
| Cited by | 23 drafts, all informatively; not in the ledger |

Recommendations keep every anchor and the three externally cited names.

## A. Corrections: fix whatever the structure decisions

1. **The capability-kill property is tied to the deployment level
   (L3247-3262), which contradicts the draft and the containment
   profile.**
   - L3247-3248: the property "tracks the deployment's assurance
     level".
   - L3260-3262: the runbook names "which capability-kill property its
     own assurance level claims".
   - Against that, the composition section (L2711-2718) says a
     Runtime-Enforced deployment can provide only the Baseline property
     for a class its Enforcement Scope Statement leaves
     lifecycle-gated-only.
   - The containment profile (its Containment Properties section,
     L596-623) makes the property per consumer: "What a consumer
     actually gets depends on which one it relies on." It adds that "a
     consumer that never consults such a source gets Baseline only".
   - The matrix row "Capability kill" (L3231) describes the Baseline
     property alone.

   Fix: derive the property from the covered action class, its
   enforcement scope, and the consumer's state source and freshness
   bound, never from the deployment level. Fix this before any
   deduplication, because B5 and B10 point at this text.
2. **"the four issuer bindings" (L1117) does not say which four.** This
   is not necessarily a counting error against "the five bindings"
   (L890). The text suggests AAuth is the one left out:
   - L1435-1447 lists the authority-bearing bindings that host the
     Mission Issuer;
   - L1459-1460 says the AAuth Person Server is "rather than an
     OAuth-style Mission Issuer".

   "Issuer binding" is defined nowhere. Name the members (likely OAuth,
   MAS, UMA, GNAP) rather than change the count.
3. **"eight primitives"** (L1771-1772), but the table has six rows
   (L1785-1790). The other two are the Mission-Bound Credential and
   Approval Fidelity subsections. Either say so, or add both as table
   rows.
4. **The "Mission-bound" definition has two stated sources and a
   misdirected pointer.** Binding Properties supplies the substance:
   six conditions. The pointer from Token Classes is navigation, not
   circularity. The real defects:
   - L1806-1809 attributes the names to the OAuth binding's
     Terminology, while L1821-1824 calls the equivalence "the
     definition";
   - L1849 says "condition 2 ... above", but the condition is about
     1,000 lines below (L2829);
   - "The OAuth binding publishes no Statement" is explained twice
     (L1827-1831, L2823-2825).

   State once which document defines the names and which defines the
   equivalence.
5. **"an Action-Enforced deployment"** (L2398): no such level exists.
   The level is Runtime-Enforced.
6. **Terms used but never defined or pointed to.** "Consequential
   action" is fine, since L506 points to its owner. These are not:
   - high-consequence classes (8 uses, first at L919; the subset of
     consequential actions);
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
11. **The binding-property summary is narrower than the vector**
    (L2971-2975). It says "a binding property says whose Mission a
    path's work and credentials are bound to". But the vector also
    covers presenter-key, instance, and action binding (L2800-2808).
    Restate it as the relationships a path establishes.

## B. Repetition: one authoritative explanation each

**Rule.** Before removing a repetition, check whether it carries a
condition the home does not: a binding, an actor, an action path, a
timing, or a residual. If it does, keep a one-sentence qualified summary
beside the claim it constrains and point to the home for the full
statement. A pointer alone must never leave a locally misleading
sentence. Deduplication happens in PR 2, alongside the move that settles
each home (F).

| # | Concept | Stated at (L) | Home | Local context that stays |
| --- | --- | --- | --- | --- |
| 1 | Mission is not a new way to express authority | 386, 410-413, 535-537, 795-808 | Introduction, first paragraph | Non-Goals keeps the RAR, GNAP, and capability comparison |
| 2 | Delegated-authority layer | 387-390, 456-461, 578-601, 1541-1563 | The Mission, with the planes diagram moved there | The Abstract's one clause |
| 3 | Bindings: peer standing and differences | 421-454, 569-576, 783-789, 1139-1144, 1509-1539, 2091-2172, 2505-2522, 3314-3320 | Binding Security Architectures (C3) | Every qualification on issuance gating, authority projection, or termination effect |
| 4 | Only `active` permits; unknown fails safe | 555-567, 1155-1160, 1786, 2599-2608, 3347-3350 | The invariant | The AAuth gated-path scope at L1161-1167 |
| 5 | What survives revocation | 558-560, 648-650, 1186-1190, 2535-2549, 2739-2748, 3231-3232, 3239-3241, 3533-3538 | Validity Model | Each site's artifact-specific bound (token, redeemed grant, attenuation root, a standalone MAS's native credential) |
| 6 | Lifetime-bounded (TTL) reliance | 1937-1975, 2147-2151, 2190, 2219-2227, 2539-2549 | Validity Model | Baseline's cutoff sentence; the issuance-only deployment's introspection cutoff; the Short Mission pattern |
| 7 | The kernel list | 1749-1757, 1984-1998, 3272-3299 | Substrate introduction | Requirements keep their numbered checklist form, pointing to the substrate; the Binding Checklist's AAuth clause moves to C3 |
| 8 | "Mission-bound" | 1806-1840, 1842-1881, 2818-2871 | Binding Properties | Token Classes keeps the one-line strong-class summary so the term is usable where it is introduced |
| 9 | Anchors commit, not semantics | 824-826, 1207-1212, 1793-1802, 2035-2050, 3542-3545 | Derivation Boundary | The invariant's line; the Security Considerations risk line |
| 10 | MAS has no token-layer kill switch | 1440-1443, 1853-1856, 2112, 2153-2166, 2512-2516, 2551-2559, 2735 | Binding Security Architectures | The MAS clauses in the Baseline level and in the composition table row; both change the guarantee |
| 11 | Claims, not levels, are what relying parties compare | 2486-2494, 2752-2757, 2779-2782, 2979-2983, 3196-3200 | Assurance Claims | None |
| 12 | Four stacks are the four levels | 1065-1103, 2524-2672 | Assurance Levels (DRAFTS.md already calls the stacks "its Mission Assurance Levels") | Reference Architecture becomes one paragraph; anchor kept |
| 13 | A work product is input, not authority | 1231-1241, 2282-2295 | The invariants' readings | One sentence in the quarantine pattern |
| 14 | Delegation chooser | 991-998, 1733-1744 | Delegate verb | None |
| 15 | Issuance join | 1877-1881, 2168-2172, 2556-2559 | Binding Security Architectures | "Restores gated issuance" in Baseline-under-MAS |
| 16 | Staleness bound + permit window + execution bound | 2621-2624, 2736, 2762-2765, 3256-3258 | Bounded Revocation Latency claim | None; referred to by name |
| 17 | The five crossovers | list 2349-2380, table 2382-2388 | The table | The list's caveats become a column |
| 18 | "The profile governs" | 398, 463-467, 498-500, 1773, 1238-1241, 1257-1260, 2483, 2577-2579, 2728-2730, 2992-2996, 3526 | Introduction L463-467 | None |
| 19 | Attribution is carried, never inferred | 1192-1199, 1608-1612 | Actor Chain | The invariant's standalone-MAS inference clause (L1196-1199) |
| 20 | Per-verb owner lists | each verb subsection, Document Map, DRAFTS.md | The overlay table (C1) | Verb subsections keep the question and the boundary |

## C. Structure

### C1. Navigate by the verbs; keep the other frames independent

The verb spine is the family's signature view and the main navigation
path. Keep it intact. Do not regroup the verbs, and do not make the
other frames subordinate to it.

- Fold the four stacks into the levels (B12).
- At the verbs section, add one overlay table with these columns:
  verb, question, boundary, owning documents, and package (D4). It
  replaces the owner lists in each verb subsection. The table has no
  level column: optional capabilities and the different binding paths
  do not fit a ladder, and a level column would read as conformance.
- Open the assurance part with a table of the questions each frame
  answers:

  | Frame | Question it answers |
  | --- | --- |
  | Verbs | What happens to a Mission and its authority |
  | Levels | Which capabilities a deployment adopts |
  | Claims | What a relying party can verify |
  | Binding properties | Which relationships a path establishes: Mission attachment, credential, presenter key, instance, action |
  | Containment properties | What actually stops, per action class and state source |
  | Deployment Profile | Where a deployment declares all of the above |

  Below the table, one sentence: a level is an adoption bundle, not a
  conformance class, and it does not determine any class's containment
  property (A1).

### C2. Order

The current order runs model, then deployment, then model again: the
derivation boundary comes after the substrate, and Requirements come
after deployment. There are also forward references:
- Capability Envelope cites assurance levels, kill-switch composition,
  binding properties, the ontology contract, and the Deployment Profile
  before any of them appears.
- The Reference Architecture uses level names about 1,400 lines before
  the levels are introduced.
- The Ontology Contract says the derivation boundary comes "later in
  this document" (L1264).

Proposed order:

1. **Introduction:** what a Mission is, why it exists, and what this
   document is. L436-461 moves to C3. Add one sentence that sorts the
   document's content into the three kinds from Verdict 4: vocabulary
   defined here, illustrative material, and rules owned elsewhere.
2. **Conventions and Terminology:** add the A6 terms, AAuth, and PS.
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
   lifecycles. Swarm Execution moves beside the Delegate verb as its
   contrast case (multiplication, not delegation). It does not go under
   Delegate, because its whole point is that it is not delegation.
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
    - Binding Security Architectures, as the comparison home for
      binding differences (C3).
11. **Assurance:**
    - the frames table;
    - the levels, absorbing the stacks;
    - claims;
    - binding properties;
    - kill-switch composition merged with the Containment Matrix
      (they overlap at L2704-2748 and L3223-3262), after A1;
    - prevention and detection.
12. **Deployment:**
    - entry ramps;
    - named pattern subsections (issuance-only, short mission,
      quarantine, standing agent; today all under one heading,
      L2174-2323);
    - the Deployment Profile, labeled illustrative.
13. **Security, Privacy, IANA.**

**Binding-neutral prose.** Do not make OAuth an implicit default.
- The model sections (4, 7, 8, and the Validity Model) state each
  concept in the substrate's binding-neutral vocabulary.
- Realizations are labeled, as "In the OAuth binding, ..." or as a row
  of the C3 table.
- The sections that are realizations by nature stay OAuth-specific and
  say so, rather than being rewritten neutral. These are the primitives
  table, Token Classes, and the OAuth-path sequence.
- Each of the 21 "(the OAuth binding's X section)" parentheticals
  becomes a `{{I-D...}}` section citation where the pointer is needed.
  It is cut where its sentence is already labeled.

Appendix candidates:

- Requirements;
- Worked Composition;
- Comparison to a Conventional Stack (table form);
- Error Surfaces and Registration Posture (L2005-2031, wire detail
  inside a substrate summary);
- Illustrative Verification Guidance (L2577-2615; see D7);
- Document Map.

**Reader split.** The cold reader proposed the same skeleton, with three
differences:

- It moves Comparison into core's "Why a New Object". Core is the
  editor's draft and issue-first, and the comparison is positioning for
  the whole family, so this review keeps it here as an appendix.
- It demotes the Deployment Profile to an appendix (D2).
- It moves the kill-switch table into the containment profile (D6).

### C3. Binding differences: one comparison home, local qualifications kept

Gather the detailed binding comparisons into Binding Security
Architectures, with a subsection "How the AAuth binding realizes the
model". Extend that section's table with rows for:

- invariants adopted;
- lifecycle states;
- approval fidelity;
- validity horizons;
- error surface;
- privacy posture.

A section keeps its local qualification wherever the difference changes
a guarantee stated there. The cases are issuance gating (which access
modes a terminated Mission stops), authority projection (whether a
subset relation exists), and termination effect (what still runs). A
carve-out that only restates a difference becomes a pointer. This is
the cross-cutting-rule move, not a demotion: the peer binding gets a
section of its own. The AAuth count is a diagnostic, not a target.

Carve-out sites to sort into "keep, qualified" and "pointer":

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
    (L2734-2737). After A1, use short cells with numbered notes, or one
    paragraph per row.
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

**Ruled 2026-10-01:** the author accepted D1-D9 as recommended, with two
binding constraints:
- The shared architecture stays binding-neutral. No passage may treat
  OAuth as the document-wide default.
- No overlay or table may map verbs or capabilities to "the first level
  that requires it". Deployment levels are adoption bundles, never
  mandatory capability ladders.

The recommendations below are those rulings. The details below them
give the options behind each.

| # | Recommendation | Reason |
| --- | --- | --- |
| D1 | Keep Binding Properties here. Change the Introduction's scope sentence to say the document defines descriptive vocabulary (binding properties, token classes, assurance levels) but no protocol or requirement, and label vocabulary, illustrative material, and rules owned elsewhere | No other document changes, and core and MAS already cite it here; a move to the substrate is a family round that buys readers nothing |
| D2 | Keep the Deployment Profile section in the body, labeled illustrative; move its two JSON shapes to an appendix | Takes about 150 lines of JSON (L3012-3131, L3167-3194) out of the body without touching the deferred schema |
| D3 | Trim each Document Map role to 15 words or fewer and move the map to an appendix | DRAFTS.md is not part of the I-D, so the map stays; generating it from the manifest needs build tooling, so do that only if drift recurs |
| D4 | Turn the Five Packages into a column of the C1 overlay table; drop the standalone list | Keeps the product architect's view without a third taxonomy section |
| D5 | Move Requirements to an appendix | No draft cites an R-number, and the body already states the kernel and invariants |
| D6 | Keep both name sets. A1 fixes the inconsistency, and the frames table says once that a level does not determine a class's containment property | The real defect is A1; renaming the containment properties changes another draft without fixing it |
| D7 | Move the Baseline verification scenarios to an appendix labeled illustrative verification guidance, and trace each one to the rule its owning document states | Their absence from the ledger does not make this document their conformance owner; L2577-2579 already says each verifies a rule its home profile states |
| D8 | Keep the comparison here as an appendix, table form only | It is family-level positioning; moving it into core is an issue-first change for no reader gain |
| D9 | Use "AuthZEN profile" in this draft (matching the companion's title) in PR 1; file one family issue for the other uses and the manifest summary; leave "Mission Capability Binding" as a title | Fixes this draft now without deciding the family cleanup inside an architecture PR |

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
  shortens the body without touching that reservation. An illustrative
  profile does not conflict with "defines no wire protocol" once it is
  labeled.
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
  invariants. No other draft cites an R-number, so a move is free.
- **D6. The level names collide with the containment properties
  (L2706-2718).** "Baseline" and "Runtime-Enforced" each mean two
  things. The collision itself is survivable once A1 is fixed and the
  frames table separates the two. Renaming the containment properties
  (for example, derivation-gated and action-gated) is the alternative,
  and it changes the containment profile.
- **D7. Verification scenarios inside Baseline Issuance
  (L2577-2615).** Neither the substrate draft nor core states these
  scenarios as tests, and no ledger row matches them one-to-one. But
  each one checks a rule its owning document states (L2577-2579 says
  so). That makes them illustrative verification guidance, not a
  conformance surface this document owns. Move them to an appendix,
  and give each its owning rule: the substrate kernel, the
  Credential-Bound and Lifecycle-Gated capabilities, or the OAuth
  binding's gates.
- **D8. Comparison to a Conventional Stack.** Keep it as an appendix
  here (table form), or move it into core's "Why a New Object" through
  an issue.
- **D9. How far does the "binding is reserved" rule (#845) reach?** This
  draft says "AuthZEN binding" 7 times (L853, L1082, L1787, L1788,
  L2621, L2637, L2911). The usage is family-wide:
  - The AuthZEN draft calls itself "the OpenID AuthZEN binding" (its
    L197 and L234), and `family-manifest.json` L547 generates the same
    words into DRAFTS.md.
  - Runtime uses the phrase 5 times and runtime-evidence 14 times.
  - A companion is titled "Mission Capability Binding".

  Either AuthZEN and capability binding are accepted exceptions, or the
  cleanup is a family round that includes the manifest summary. It is
  not an architecture-only fix.

## F. Application plan

Three PRs, in order. Deduplication depends on where each concept lands,
so it moves with the structure, not ahead of it.

1. **Corrections (A, and D9 within this draft).**
   - A1 first; then the other confirmed corrections and the Conventions
     entries for the A6 terms.
   - No deduplication and no moves.
2. **Reading order and section ownership (C, with D1-D8 as ruled).**
   - A scripted reassembly with `spec_units.py`, anchors unchanged.
   - Deduplication happens alongside each move, under the B rule.
   - Regenerate the DRAFTS.md row summary.
   - Then a post-churn consistency read for pointers whose target no
     longer says what the citing sentence claims.
3. **Paragraph and table simplification (D).** Section owners work in
   parallel within a fixed word budget, followed by a condition
   verifier.

**Acceptance, each PR.** The mechanical checks are necessary, but they
are weak evidence that meaning survived in an Informational document:
- the build passes;
- the BCP 14 sequence is unchanged apart from the A8 lowercasing;
- every anchor and the three cited names are kept.

So each PR also passes reader checks. A cold reader answers the
questions below from the draft, quoting the passage that answers each,
on main and on the PR head. A PR passes when no answer gets worse and
every quote still supports its answer.

1. What separates a Mission-referenced credential from Mission-bound
   authority?
2. For a given action class, what determines whether a capability kill
   stops an already-issued token: the deployment level, or something
   else?
3. When a Mission is terminated, what stops at once, and what keeps
   running to its own bound?
4. Under the AAuth binding, which access modes does a terminated
   Mission stop?
5. Which binding-property dimensions does a Mission Join Assertion
   establish, and which does it not?

The total falls out of these moves. No figure is promised.
