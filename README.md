# SIGMASimTest

# Detection Rule Event-Set Similarity

Compare two detection rules and determine whether they match the **same underlying events**.

This is a portable replica of the Sigma similarity/novelty engine that runs inside
Huntable CTI Studio. It is pure deterministic set math: **PyYAML + stdlib only**.

---

## Purpose

Answer one question only:

**Would the exact same EDR / SIEM events match both rules?**

---

## Scope

✔ Deterministic
✔ Event-set based
✔ Detection-as-code friendly

✘ Behavioral similarity
✘ MITRE / intent comparison
✘ Alert volume estimation
✘ Embeddings / cosine / RAG

No embeddings. No cosine similarity. No metadata comparison. No fuzzy matching.
No database. No network calls. No global mutable state.

---

## The formula

```
similarity = clamp01( Jaccard × Containment − FilterPenalty )
```

That is the whole score. Positive atoms drive Jaccard, containment adjusts for
directionality and logical breadth, and filters can only ever *reduce* the result.

---

## Install

```bash
pip install -e .
```

Python ≥ 3.11. PyYAML is the only dependency.

---

## Usage

```bash
sigma-similarity compare examples/rule1.yaml examples/rule2.yaml
sigma-similarity index rules/ -o corpus.json
sigma-similarity assess new_rule.yaml --corpus corpus.json
sigma-similarity assess --batch proposed/ --corpus corpus.json
```

A bare two-argument invocation still runs `compare`:

```bash
sigma-similarity examples/rule1.yaml examples/rule2.yaml
```

`python3 -m sigma_similarity ...` mirrors the CLI.

### API

```python
from sigma_similarity import compare_rules, SimilarityResult

result = compare_rules(rule_a, rule_b)   # dicts or YAML strings
result.similarity, result.jaccard, result.explanation["reason_flags"]
```

Exit codes: `0` structured result; `1` file/parse errors, `UnknownTelemetryClassError`,
`UnsupportedSigmaFeatureError`; `2` usage.

---

## Pipeline

```
Sigma YAML
  ├─► resolve_canonical_class(rule)          hard gate
  └─► normalize_detection(detection)         tokenize + parse the condition
        └─► build_ast()                      AND / OR / NOT / Atom
              └─► ast_to_dnf()               branches (max 64)
                    ├─► positive atoms       set[str]
                    ├─► negative atoms       set[str]
                    └─► surface score        float(branch count)
```

---

## Atom identity

Every predicate collapses to a **3-slot identity**:

```
field | modifier_chain | normalized_value
```

The operator is **not** a separate slot — it is always `modifier_chain.split("|")[0]`,
and an empty chain means the default `eq`. Emitting it separately is what produced the
old `endswith|endswith` duplication.

| Rule fragment | Atom identity |
|---|---|
| `CommandLine\|contains: "Invoke-WebRequest"` | `process.command_line\|contains\|invoke-webrequest` |
| `Image\|endswith: '\powershell.exe'` | `process.image\|endswith\|/powershell.exe` |
| `Image: "cmd.exe"` (no modifier) | `process.image\|\|cmd.exe` |
| keyword-list scalar `"<script>"` | `\|contains\|<script>` |

Normalization rules:

- **Field aliasing** is case-insensitive and three-tiered: exact `FIELD_ALIAS_MAP` hit →
  lowercase/snake_case overlay → `field.lower()` as-is. So `CommandLine`,
  `ProcessCommandLine` and `command_line` all become `process.command_line`.
- **Case folding**: `contains`, `endswith`, `startswith` and `eq` are case-insensitive in
  Sigma, so their values fold to lowercase. The `|cased` modifier preserves case — a rule
  hunting a specific literal casing is real tradecraft signal and must not collapse into
  its case-insensitive sibling. `re` values always preserve case.
- **Backslashes**: doubled backslashes are preserved, single `\` becomes `/`.
- **Edge wildcard folding**: `CommandLine: "*foo*"` and `CommandLine|contains: "foo"`
  produce a byte-identical atom. Only *edge* wildcards fold — internal `foo*bar*baz` is
  left alone, and `re`/numeric operators never fold (`*` is a literal pattern char there).

Atoms are rendered for display only at emit time, as `field|op:value`
(or `field:value` when the chain is empty). All set math runs on raw identities.

> **Does this discard attacker signal?** No. There is no fuzzy, spelling or edit-distance
> matching anywhere, so misspellings and homoglyph binary names are never merged. Case
> folds only where Sigma itself matches case-insensitively — meaning both forms already
> hit the same events, so the two rules are genuine duplicates. Full reasoning, worked
> examples and measured impact: **[docs/matching-semantics.md](docs/matching-semantics.md)**.

### Polarity

Polarity comes **exclusively from the condition AST**. Negation is whatever `not` makes
negative — a selection named `filter*` that is referenced positively is a positive atom.
A branch consisting only of negated literals contributes nothing, because the engine
cannot reason about a naked NOT under OR.

---

## Canonical telemetry class gate

Every rule must resolve to one of **21 canonical telemetry classes** from its
`(product, category, service, event_id)` tuple. `event_id` is read out of the detection
block, accepting `EventID`, `EventId`, `eventid`, `event_id`, `EventCode`, `eventcode`
and `event_code` — `EventCode` matters because Splunk-backend rules emit it.

Matching is exact tuple equality; a `None` slot in the registry means the rule's slot must
also be `None`, not "anything".

**Consolidated deliberately:** all `registry_*` categories are one class (same Sysmon
EIDs 12–14, same `TargetObject` field); all `file_*` categories are one class.

**Split deliberately:** the three PowerShell channels (4104 `ScriptBlockText` / 4103
`Payload` / 400 `Data` — different EID *and* field); `web.webserver` vs `web.proxy`;
`windows.dns_query` (`QueryName`) vs `network.dns` (`query`); and windows / linux / macos
process creation, since cross-OS comparison would read as false-similar.

**Known limitation:** scheduled-task tradecraft is visible through process_creation
(`schtasks.exe`), file_event (`\Tasks\` writes) and registry_event (TaskCache), and those
stay in separate buckets. That can produce a false NOVEL. This is documented, not fixed.

Two failure modes, deliberately different:

| Situation | Result |
|---|---|
| Rule maps to **no** class | `UnknownTelemetryClassError` is **raised** |
| Two rules map to **different** classes | `similarity = 0.0`, `reason_flags = ["canonical_class_mismatch"]` |

---

## Condition grammar

Supported:

```
disjunction → conjunction (OR conjunction)*
conjunction → unary (AND unary)*
unary       → NOT unary | primary
primary     → "(" disjunction ")" | "1" "of" primary | "all" "of" primary | IDENT
```

- Boolean `and` / `or` / `not`, parentheses, arbitrary nesting
- Selection references, including `selection*` prefix wildcards
- Quantifiers `1 of selection*` (OR) and `all of selection*` (AND)
- Value lists → OR; lists under an `|all` modifier → AND
- A **list of maps** is an OR of blocks, not one merged block
- A **list of bare scalars** (keyword selection) becomes field-less `|contains|<value>`
  atoms, so webserver/XSS/SSTI keyword rules extract real atoms instead of silently
  producing none

Rejected — these raise `UnsupportedSigmaFeatureError`: `count()`, `near`, temporal joins,
aggregation, correlation, sequence operators, a list-valued `condition`, a missing
`condition`, an unresolvable selection reference, and an empty DNF.

---

## Scoring

**Jaccard** over positive atoms. An empty intersection short-circuits to
`similarity = 0.0` with `reason_flags = ["no_shared_atoms"]` rather than a misleading
percentage.

**Containment** is a four-way bucket over the directional overlap ratios and the surface
(DNF branch count) of each rule:

| Bucket | Condition | Factor |
|---|---|---|
| Equivalent | `overlap_a ≥ 0.9` and `overlap_b ≥ 0.9` and `surface_ratio ≤ 0.10` | **1.00** |
| Subset | `overlap_a ≥ 0.9` and `surface_a < surface_b` | **0.85** |
| Superset | `overlap_b ≥ 0.9` and `surface_a > surface_b` | **0.75** |
| Partial | anything else | **0.65** |

**Filter penalty** is `min(0.5, |F₁ △ F₂| / max(|A₁|, |A₂|))`, and `0.0` when the
denominator is zero. Negative atoms never enter the positive Jaccard.

> ### Naming trap: `containment` vs `containment_factor`
>
> These are two different numbers returned by the same function, and conflating them was
> a real bug.
>
> - **`containment`** is `overlap_ratio_a` — the raw directional ratio, "how much of rule
>   A is covered by rule B".
> - **`containment_factor`** is the four-way bucket above (1.0 / 0.85 / 0.75 / 0.65).
>   Huntable's UI labels this one "Logic Shape".

There is no service penalty and no logic-shape similarity. Both are gone.

---

## Novelty layer

The engine scores pairs. The novelty layer answers "have we already got this rule?"
against a corpus.

```bash
sigma-similarity index rules/ -o corpus.json
sigma-similarity assess proposed.yaml --corpus corpus.json --rules-dir rules/
```

**Indexing is strict.** A rule that resolves to no canonical class is *retained* with null
atom fields and `skip_reason: "logsource_unresolved"` — not dropped, not an error. Same for
`dnf_expansion_limit` and `unsupported_sigma_feature`. Persisting the reason per rule is
deliberate: a null atom field must always stay distinguishable from "indexing failed".

**Exact hash.** SHA-256 over `{canonical_class, positive_atoms, negative_atoms,
surface_score}`. An identical hash means DUPLICATE, short-circuiting all scoring. Rules
with **no positive atoms hash to `None`**, and the retrieval probe only runs when the
proposed hash is not `None`. Both guards are load-bearing: atom-less rules collapse to a
single degenerate canonical form, and without them `NULL == NULL` matches everything. In
Huntable this once put 84 unrelated process_creation rules on one hash and silently
suppressed novel rules.

**Retrieval** runs in three ordered phases: exact-hash probe (first hit returns
immediately) → canonical-class match (unlimited) → logsource fallback (equal
`product|category`, sorted by `rule_id`, truncated to `--top-k`). Sorting before
truncation is what makes the top-k stable. The logsource gate is applied only on the
fallback path; on the class path the filter is already authoritative, and on the hash path
identity is proof.

**Classification** is per match, never broadcast from the best match to the rest:

| Similarity | Label |
|---|---|
| exact hash match, or `≥ 0.75` | `DUPLICATE` |
| `≥ 0.50` | `SIMILAR` |
| below that | `NOVEL` |

Both boundaries are inclusive.

**`NEEDS_REVIEW` fails open.** A rule is *inconclusive* when it extracted zero atoms, or
when candidates **were** retrieved but none shared any behavior. An unassessable rule is a
*failure to assess* — never silently passed as novel, never suppressed.

This makes `NOVEL` deliberately narrow, and it is worth being explicit about: `NOVEL`
means **no candidates were retrieved at all**. If the corpus contains same-class rules and
the proposed rule overlaps with none of them, the verdict is `NEEDS_REVIEW`, not `NOVEL` —
zero overlap against a populated class is more often an extraction problem than genuine
novelty, so a human looks at it.

| Case | `max_similarity` | Verdict |
|---|---|---|
| Empty corpus (or no candidates retrieved), atoms extracted fine | `0.0` | `NOVEL` |
| Proposed rule extracted zero atoms | `null` | `NEEDS_REVIEW` |
| Candidates retrieved, none share an atom | `null` | `NEEDS_REVIEW` |

Collapsing the first two once disabled novelty suppression for ~86% of Huntable's queue,
which is why `max_similarity` is `null` rather than `0.0` whenever the result is
inconclusive.

In batch mode the verdict is computed **per rule** — one near-duplicate never suppresses
its novel siblings.

**Soft-exe fallback.** When strict Jaccard is 0, the engine looks for the same executable
value across process-related fields (`rundll32.exe` in `Image` on one side, in
`CommandLine` on the other). A shared value yields a score dampened by 0.5, flagged
`soft_exe_match` so it stays explainable. Disable with `--no-soft-exe`.

---

## Expected output

Generated by the current engine against `examples/`. These are the golden acceptance
vectors and are byte-compared in the test suite.

`compare examples/rule1.yaml examples/rule3.yaml` — identical event sets:

```json
{"canonical_class":"windows.process_creation","containment_factor":1.0,"explanation":{"overlap_ratio_a":1.0,"overlap_ratio_b":1.0,"reason_flags":[]},"filter_penalty":0.0,"jaccard":1.0,"similarity":1.0,"surface_score_a":8.0,"surface_score_b":8.0}
```

`compare examples/rule1.yaml examples/rule2.yaml` — partial atom overlap, divergent filters:

```json
{"canonical_class":"windows.process_creation","containment_factor":0.65,"explanation":{"overlap_ratio_a":0.5,"overlap_ratio_b":0.5,"reason_flags":[]},"filter_penalty":0.3333333333333333,"jaccard":0.3333333333333333,"similarity":0.0,"surface_score_a":8.0,"surface_score_b":8.0}
```

`compare examples/rule2.yaml examples/rule3.yaml` produces output identical to the pair
above.

The second result is worth reading carefully: `0.3333 × 0.65 − 0.3333 ≈ −0.117`, clamped
to `0.0`. The rules share a third of their atoms, but their filter logic diverges enough
to wipe out the overlap. Earlier versions of this repo reported `0.4333` for that pair
under a since-deleted weighted formula.

### Assess match shape

```jsonc
{
  "rule_id": "...", "title": "...", "novelty_label": "SIMILAR",
  "similarity": 0.5525, "jaccard": 0.85, "containment_factor": 0.65,
  "containment": 0.85,
  "overlap_ratio_a": 0.85, "overlap_ratio_b": 0.62,
  "filter_penalty": 0.0, "surface_score_a": 8, "surface_score_b": 5,
  "canonical_class": "windows.process_creation",
  "exact_hash_match": false, "phase1_path": "canonical_class",
  "reason_flags": [],
  "shared_atoms": ["..."], "atoms_only_in_a": ["..."], "atoms_only_in_b": ["..."],
  "filter_differences": ["..."]
}
```

Floats are rounded to 4 decimal places in the `assess` shape; `compare` emits raw floats.

---

## Errors

| Error | Meaning |
|---|---|
| `UnsupportedSigmaFeatureError` | Unsupported condition or detection feature (see the rejected list) |
| `UnknownTelemetryClassError` | Rule maps to no canonical telemetry class — raised, never converted to a result |
| `DeterministicExpansionLimitError` | DNF would exceed 64 branches. `compare_rules` catches it and returns `similarity = 0.0` with `reason_flags = ["dnf_expansion_limit"]`, so it never escapes the CLI |

---

## Determinism

Same input → byte-identical output. Atoms and DNF branches are canonically sorted, JSON is
emitted with `sort_keys=True, separators=(",", ":")`, and there is no global state, no
wall-clock and no randomness anywhere. The test suite verifies output stability across
`PYTHONHASHSEED` values.

---

## Known differences from Huntable

- **Hashes are not cross-compatible** with Huntable's DB `exact_hash` column, which hashes
  its app-side canonical-rule JSON. Only the *semantics* are the contract: identical
  canonical form means duplicate, atom-less means never hash.
- **`_normalize_atom_identity` is not ported.** That lowercase-whole-identity safety net
  exists only to reconcile atoms extracted by *different engine versions* sharing one
  database. This tool always extracts with a single engine version per run.
- **`near_hash` is not ported** — a schema vestige, unused on the live path.
- **Only the current classification rule is implemented.** Huntable still carries a legacy
  backend rule (strict `>` on `atom_jaccard` 0.95/0.80 plus a `logic_shape` input) that
  predates the engine consolidation. It is deliberately not replicated.
- **Double negation** (`not (not filter)`) is unsupported by the DNF normalizer. It fails
  loudly — the empty-DNF guard raises, and the novelty layer turns that into
  `NEEDS_REVIEW` — rather than silently scoring a truncated atom set.

Out of scope entirely: the web UI, queue workflow and approval states; Postgres/pgvector;
article→rule matching; and the DB-coupled eval-pair miner.

---

## Development

```bash
pip install -e . && pytest
```

The suite covers atom identity and folding, the condition grammar, DNF canonicalization,
containment buckets, full registry resolvability, the novelty layer, the golden vectors,
and determinism. Every test encodes a behavior that fixed a real shipped bug — they are
regression contracts, not illustrations.

Further reading: **[docs/matching-semantics.md](docs/matching-semantics.md)** covers what is
and isn't normalized, and why. `tests/test_matching_semantics_doc.py` is its executable
contract — change the engine's normalization behavior and that suite fails, so the document
cannot silently go stale.

---

## Design Principles

- Rules are executable logic
- Similarity must be provable
- Fail conservatively
- No inference without telemetry

---

## License

MIT
